/**
 * Human-like random email local-part generator.
 * Combines two Indonesian word lists + optional number suffix.
 * Ported from the original tempmail VPS project, then expanded.
 */

const FIRST = [
  // Alam / nature
  'langit', 'senja', 'pagi', 'malam', 'kopi', 'hujan', 'bulan', 'bintang', 'angin', 'awan',
  'nusa', 'rasa', 'jalan', 'teman', 'cerita', 'warna', 'nadi', 'cahya', 'putra', 'putri',
  'bagas', 'adit', 'arya', 'dimas', 'fajar', 'rizky', 'galih', 'bayu', 'bima', 'nanda',
  'mega', 'surya', 'gunung', 'lembah', 'samudra', 'rimba', 'danau', 'pelangi', 'gemericik', 'embun',
  'pelita', 'akhasa', 'sahara', 'karang', 'rawa', 'gurun', 'pantai', 'matahari', 'rembulan', 'galaksi',
  // Hewan / animals
  'elang', 'macan', 'rajawali', 'garuda', 'merak', 'kancil', 'naga', 'kuda', 'cendrawasih', 'lumba',
  'harimau', 'cicak', 'jalak', 'tekukur', 'kenari', 'merpati', 'kumbang', 'lebah', 'kupu', 'belalang',
  // Tumbuhan / plants
  'melati', 'mawar', 'anggrek', 'teratai', 'cemara', 'pinus', 'jati', 'rotan', 'randu', 'mangga',
  'durian', 'rambutan', 'nangka', 'pisang', 'nanas', 'salak', 'duku', 'pepaya', 'sirsak', 'manggis',
  // Nama orang / people
  'ananta', 'arjuna', 'bisma', 'dewa', 'dewi', 'galuh', 'kresna', 'sinta', 'wibawa', 'wisesa',
  'agung', 'abimanyu', 'cakra', 'dananjaya', 'prabu', 'ratna', 'sakti', 'satria', 'wira', 'widya',
];

const SECOND = [
  // Warna / colors
  'biru', 'jingga', 'ungu', 'merah', 'kuning', 'hijau', 'putih', 'emas', 'perak', 'abuabu',
  'nila', 'merona', 'kelabu', 'keemasan', 'kebiruan', 'lembayung', 'merjan', 'dadumuda', 'coklat', 'krem',
  // Sifat / traits
  'manis', 'tenang', 'indah', 'muda', 'asri', 'jaya', 'lucu', 'syahdu', 'harum', 'utama',
  'cerdas', 'cepat', 'lembut', 'hangat', 'murni', 'setia', 'mulia', 'ramah', 'santun', 'gembira',
  'perkasa', 'ganas', 'kencang', 'sabar', 'ikhlas', 'tabah', 'cermat', 'cekatan', 'lapang', 'damai',
  // Alam / nature 2
  'laut', 'hutan', 'cerah', 'pagi', 'malam', 'kecil', 'besar', 'dedaunan', 'samudra', 'rimbun',
  'gunung', 'lembah', 'sawah', 'kali', 'pulau', 'tebing', 'gua', 'padang', 'rawa', 'bukit',
  // Benda / objects
  'aji', 'wira', 'ayu', 'sari', 'nugraha', 'permata', 'lestari', 'mahesa', 'karya', 'puspa',
  'rasa', 'bakti', 'citra', 'daya', 'dharma', 'gita', 'jiwa', 'karsa', 'kencana', 'loka',
  'mustika', 'nirmala', 'bentala', 'gerhana', 'kirana', 'mahkota', 'mentari', 'nusantara', 'purnama', 'sejati',
];

function pick<T>(arr: T[]): T {
  return arr[secureRandInt(arr.length)];
}

// ─────────────────────────────────────────────────────────────────────────────
// ENTROPY
//
// The word lists are published in this repository, so `first + second + nn`
// was drawn from a space of only 110 * 100 * 91 = 1,001,000 addresses per
// domain — and an address IS the only credential for an inbox that has not been
// locked. Anyone could enumerate that space (34 domains -> ~34M candidates) and
// harvest the OTPs landing in inboxes nobody locked.
//
// A random token from a CSPRNG is now appended, so the address is no longer
// predictable from public inputs. 6 characters over a 33-symbol alphabet is
// ~1.3 x 10^9, taking the per-domain space to ~10^15.
// ─────────────────────────────────────────────────────────────────────────────

// No l / 0 / 1 so generated addresses stay easy to read and retype.
const TOKEN_ALPHABET = 'abcdefghijkmnopqrstuvwxyz23456789';
const TOKEN_LENGTH = 6;

/** Uniform random integer in [0, max) using the platform CSPRNG. */
function secureRandInt(max: number): number {
  const buf = new Uint32Array(1);
  const limit = Math.floor(0x100000000 / max) * max;
  let v = 0;
  do {
    crypto.getRandomValues(buf);
    v = buf[0];
  } while (v >= limit);
  return v % max;
}

/** Uniform random token; rejection sampling avoids modulo bias. */
function randomToken(len: number): string {
  const max = Math.floor(256 / TOKEN_ALPHABET.length) * TOKEN_ALPHABET.length;
  let out = '';
  while (out.length < len) {
    const bytes = crypto.getRandomValues(new Uint8Array(len));
    for (const b of bytes) {
      if (b >= max) continue;
      out += TOKEN_ALPHABET[b % TOKEN_ALPHABET.length];
      if (out.length === len) break;
    }
  }
  return out;
}

function randomLocalPart(): string {
  const useNumber = secureRandInt(10) < 8;
  const suffix = useNumber ? String(secureRandInt(90) + 10) : '';
  return `${pick(FIRST)}${pick(SECOND)}${suffix}-${randomToken(TOKEN_LENGTH)}`;
}

export async function generateUniqueAddress(
  exists: (addr: string) => Promise<boolean>,
  domain: string
): Promise<string> {
  for (let i = 0; i < 50; i++) {
    const address = `${randomLocalPart()}@${domain}`;
    if (!(await exists(address))) {
      return address;
    }
  }

  // Fallback: add timestamp suffix for uniqueness
  const fallback = `${randomLocalPart()}${Date.now().toString().slice(-4)}@${domain}`;
  if (!(await exists(fallback))) {
    return fallback;
  }

  throw new Error('Failed to generate unique inbox address');
}
