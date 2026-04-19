// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * crypto-utils.js
 *
 * Crypto utilities for E2E encryption in WS Messenger
 * X25519 ECDH + AES-256-GCM
 *
 * Key wrapping format (version 0x02):
 *   [0]      : 0x02 â€” version tag (X25519 ECDH)
 *   [1..32]  : ephemeral X25519 public key (32 bytes)
 *   [33..44] : AES-GCM IV (12 bytes)
 *   [45..]   : AES-GCM ciphertext (plaintext + 16-byte auth tag)
 *
 * The entire blob is base64-encoded for transport / DB storage.
 */

// BIP39 English wordlist (2048 words, BIP-0039 standard)
const _BIP39_WORDLIST = [
  "abandon","ability","able","about","above","absent","absorb","abstract","absurd","abuse",
  "access","accident","account","accuse","achieve","acid","acoustic","acquire","across","act",
  "action","actor","actress","actual","adapt","add","addict","address","adjust","admit",
  "adult","advance","advice","aerobic","affair","afford","afraid","again","age","agent",
  "agree","ahead","aim","air","airport","aisle","alarm","album","alcohol","alert",
  "alien","all","alley","allow","almost","alone","alpha","already","also","alter",
  "always","amateur","amazing","among","amount","amused","analyst","anchor","ancient","anger",
  "angle","angry","animal","ankle","announce","annual","another","answer","antenna","antique",
  "anxiety","any","apart","apology","appear","apple","approve","april","arch","arctic",
  "area","arena","argue","arm","armed","armor","army","around","arrange","arrest",
  "arrive","arrow","art","artefact","artist","artwork","ask","aspect","assault","asset",
  "assist","assume","asthma","athlete","atom","attack","attend","attitude","attract","auction",
  "audit","august","aunt","author","auto","autumn","average","avocado","avoid","awake",
  "aware","away","awesome","awful","awkward","axis","baby","bachelor","bacon","badge",
  "bag","balance","balcony","ball","bamboo","banana","banner","bar","barely","bargain",
  "barrel","base","basic","basket","battle","beach","bean","beauty","because","become",
  "beef","before","begin","behave","behind","believe","below","belt","bench","benefit",
  "best","betray","better","between","beyond","bicycle","bid","bike","bind","biology",
  "bird","birth","bitter","black","blade","blame","blanket","blast","bleak","bless",
  "blind","blood","blossom","blouse","blue","blur","blush","board","boat","body",
  "boil","bomb","bone","bonus","book","boost","border","boring","borrow","boss",
  "bottom","bounce","box","boy","bracket","brain","brand","brass","brave","bread",
  "breeze","brick","bridge","brief","bright","bring","brisk","broccoli","broken","bronze",
  "broom","brother","brown","brush","bubble","buddy","budget","buffalo","build","bulb",
  "bulk","bullet","bundle","bunker","burden","burger","burst","bus","business","busy",
  "butter","buyer","buzz","cabbage","cabin","cable","cactus","cage","cake","call",
  "calm","camera","camp","can","canal","cancel","candy","cannon","canoe","canvas",
  "canyon","capable","capital","captain","car","carbon","card","cargo","carpet","carry",
  "cart","case","cash","casino","castle","casual","cat","catalog","catch","category",
  "cattle","caught","cause","caution","cave","ceiling","celery","cement","census","century",
  "cereal","certain","chair","chalk","champion","change","chaos","chapter","charge","chase",
  "chat","cheap","check","cheese","chef","cherry","chest","chicken","chief","child",
  "chimney","choice","choose","chronic","chuckle","chunk","churn","cigar","cinnamon","circle",
  "citizen","city","civil","claim","clap","clarify","claw","clay","clean","clerk",
  "clever","click","client","cliff","climb","clinic","clip","clock","clog","close",
  "cloth","cloud","clown","club","clump","cluster","clutch","coach","coast","coconut",
  "code","coffee","coil","coin","collect","color","column","combine","come","comfort",
  "comic","common","company","concert","conduct","confirm","congress","connect","consider","control",
  "convince","cook","cool","copper","copy","coral","core","corn","correct","cost",
  "cotton","couch","country","couple","course","cousin","cover","coyote","crack","cradle",
  "craft","cram","crane","crash","crater","crawl","crazy","cream","credit","creek",
  "crew","cricket","crime","crisp","critic","crop","cross","crouch","crowd","crucial",
  "cruel","cruise","crumble","crunch","crush","cry","crystal","cube","culture","cup",
  "cupboard","curious","current","curtain","curve","cushion","custom","cute","cycle","dad",
  "damage","damp","dance","danger","daring","dash","daughter","dawn","day","deal",
  "debate","debris","decade","december","decide","decline","decorate","decrease","deer","defense",
  "define","defy","degree","delay","deliver","demand","demise","denial","dentist","deny",
  "depart","depend","deposit","depth","deputy","derive","describe","desert","design","desk",
  "despair","destroy","detail","detect","develop","device","devote","diagram","dial","diamond",
  "diary","dice","diesel","diet","differ","digital","dignity","dilemma","dinner","dinosaur",
  "direct","dirt","disagree","discover","disease","dish","dismiss","disorder","display","distance",
  "divert","divide","divorce","dizzy","doctor","document","dog","doll","dolphin","domain",
  "donate","donkey","donor","door","dose","double","dove","draft","dragon","drama",
  "drastic","draw","dream","dress","drift","drill","drink","drip","drive","drop",
  "drum","dry","duck","dumb","dune","during","dust","dutch","duty","dwarf",
  "dynamic","eager","eagle","early","earn","earth","easily","east","easy","echo",
  "ecology","economy","edge","edit","educate","effort","egg","eight","either","elbow",
  "elder","electric","elegant","element","elephant","elevator","elite","else","embark","embody",
  "embrace","emerge","emotion","employ","empower","empty","enable","enact","end","endless",
  "endorse","enemy","energy","enforce","engage","engine","enhance","enjoy","enlist","enough",
  "enrich","enroll","ensure","enter","entire","entry","envelope","episode","equal","equip",
  "era","erase","erode","erosion","error","erupt","escape","essay","essence","estate",
  "eternal","ethics","evidence","evil","evoke","evolve","exact","example","excess","exchange",
  "excite","exclude","excuse","execute","exercise","exhaust","exhibit","exile","exist","exit",
  "exotic","expand","expect","expire","explain","expose","express","extend","extra","eye",
  "eyebrow","fabric","face","faculty","fade","faint","faith","fall","false","fame",
  "family","famous","fan","fancy","fantasy","farm","fashion","fat","fatal","father",
  "fatigue","fault","favorite","feature","february","federal","fee","feed","feel","female",
  "fence","festival","fetch","fever","few","fiber","fiction","field","figure","file",
  "film","filter","final","find","fine","finger","finish","fire","firm","first",
  "fiscal","fish","fit","fitness","fix","flag","flame","flash","flat","flavor",
  "flee","flight","flip","float","flock","floor","flower","fluid","flush","fly",
  "foam","focus","fog","foil","fold","follow","food","foot","force","forest",
  "forget","fork","fortune","forum","forward","fossil","foster","found","fox","fragile",
  "frame","frequent","fresh","friend","fringe","frog","front","frost","frown","frozen",
  "fruit","fuel","fun","funny","furnace","fury","future","gadget","gain","galaxy",
  "gallery","game","gap","garage","garbage","garden","garlic","garment","gas","gasp",
  "gate","gather","gauge","gaze","general","genius","genre","gentle","genuine","gesture",
  "ghost","giant","gift","giggle","ginger","giraffe","girl","give","glad","glance",
  "glare","glass","glide","glimpse","globe","gloom","glory","glove","glow","glue",
  "goat","goddess","gold","good","goose","gorilla","gospel","gossip","govern","gown",
  "grab","grace","grain","grant","grape","grass","gravity","great","green","grid",
  "grief","grit","grocery","group","grow","grunt","guard","guess","guide","guilt",
  "guitar","gun","gym","habit","hair","half","hammer","hamster","hand","happy",
  "harbor","hard","harsh","harvest","hat","have","hawk","hazard","head","health",
  "heart","heavy","hedgehog","height","hello","helmet","help","hen","hero","hidden",
  "high","hill","hint","hip","hire","history","hobby","hockey","hold","hole",
  "holiday","hollow","home","honey","hood","hope","horn","horror","horse","hospital",
  "host","hotel","hour","hover","hub","huge","human","humble","humor","hundred",
  "hungry","hunt","hurdle","hurry","hurt","husband","hybrid","ice","icon","idea",
  "identify","idle","ignore","ill","illegal","illness","image","imitate","immense","immune",
  "impact","impose","improve","impulse","inch","include","income","increase","index","indicate",
  "indoor","industry","infant","inflict","inform","inhale","inherit","initial","inject","injury",
  "inmate","inner","innocent","input","inquiry","insane","insect","inside","inspire","install",
  "intact","interest","into","invest","invite","involve","iron","island","isolate","issue",
  "item","ivory","jacket","jaguar","jar","jazz","jealous","jeans","jelly","jewel",
  "job","join","joke","journey","joy","judge","juice","jump","jungle","junior",
  "junk","just","kangaroo","keen","keep","ketchup","key","kick","kid","kidney",
  "kind","kingdom","kiss","kit","kitchen","kite","kitten","kiwi","knee","knife",
  "knock","know","lab","label","labor","ladder","lady","lake","lamp","language",
  "laptop","large","later","latin","laugh","laundry","lava","law","lawn","lawsuit",
  "layer","lazy","leader","leaf","learn","leave","lecture","left","leg","legal",
  "legend","leisure","lemon","lend","length","lens","leopard","lesson","letter","level",
  "liar","liberty","library","license","life","lift","light","like","limb","limit",
  "link","lion","liquid","list","little","live","lizard","load","loan","lobster",
  "local","lock","logic","lonely","long","loop","lottery","loud","lounge","love",
  "loyal","lucky","luggage","lumber","lunar","lunch","luxury","lyrics","machine","mad",
  "magic","magnet","maid","mail","main","major","make","mammal","man","manage",
  "mandate","mango","mansion","manual","maple","marble","march","margin","marine","market",
  "marriage","mask","mass","master","match","material","math","matrix","matter","maximum",
  "maze","meadow","mean","measure","meat","mechanic","medal","media","melody","melt",
  "member","memory","mention","menu","mercy","merge","merit","merry","mesh","message",
  "metal","method","middle","midnight","milk","million","mimic","mind","minimum","minor",
  "minute","miracle","mirror","misery","miss","mistake","mix","mixed","mixture","mobile",
  "model","modify","mom","moment","monitor","monkey","monster","month","moon","moral",
  "more","morning","mosquito","mother","motion","motor","mountain","mouse","move","movie",
  "much","muffin","mule","multiply","muscle","museum","mushroom","music","must","mutual",
  "myself","mystery","myth","naive","name","napkin","narrow","nasty","nation","nature",
  "near","neck","need","negative","neglect","neither","nephew","nerve","nest","net",
  "network","neutral","never","news","next","nice","night","noble","noise","nominee",
  "noodle","normal","north","nose","notable","note","nothing","notice","novel","now",
  "nuclear","number","nurse","nut","oak","obey","object","oblige","obscure","observe",
  "obtain","obvious","occur","ocean","october","odor","off","offer","office","often",
  "oil","okay","old","olive","olympic","omit","once","one","onion","online",
  "only","open","opera","opinion","oppose","option","orange","orbit","orchard","order",
  "ordinary","organ","orient","original","orphan","ostrich","other","outdoor","outer","output",
  "outside","oval","oven","over","own","owner","oxygen","oyster","ozone","pact",
  "paddle","page","pair","palace","palm","panda","panel","panic","panther","paper",
  "parade","parent","park","parrot","party","pass","patch","path","patient","patrol",
  "pattern","pause","pave","payment","peace","peanut","pear","peasant","pelican","pen",
  "penalty","pencil","people","pepper","perfect","permit","person","pet","phone","photo",
  "phrase","physical","piano","picnic","picture","piece","pig","pigeon","pill","pilot",
  "pink","pioneer","pipe","pistol","pitch","pizza","place","planet","plastic","plate",
  "play","please","pledge","pluck","plug","plunge","poem","poet","point","polar",
  "pole","police","pond","pony","pool","popular","portion","position","possible","post",
  "potato","pottery","poverty","powder","power","practice","praise","predict","prefer","prepare",
  "present","pretty","prevent","price","pride","primary","print","priority","prison","private",
  "prize","problem","process","produce","profit","program","project","promote","proof","property",
  "prosper","protect","proud","provide","public","pudding","pull","pulp","pulse","pumpkin",
  "punch","pupil","puppy","purchase","purity","purpose","purse","push","put","puzzle",
  "pyramid","quality","quantum","quarter","question","quick","quit","quiz","quote","rabbit",
  "raccoon","race","rack","radar","radio","rail","rain","raise","rally","ramp",
  "ranch","random","range","rapid","rare","rate","rather","raven","raw","razor",
  "ready","real","reason","rebel","rebuild","recall","receive","recipe","record","recycle",
  "reduce","reflect","reform","refuse","region","regret","regular","reject","relax","release",
  "relief","rely","remain","remember","remind","remove","render","renew","rent","reopen",
  "repair","repeat","replace","report","require","rescue","resemble","resist","resource","response",
  "result","retire","retreat","return","reunion","reveal","review","reward","rhythm","rib",
  "ribbon","rice","rich","ride","ridge","rifle","right","rigid","ring","riot",
  "ripple","risk","ritual","rival","river","road","roast","robot","robust","rocket",
  "romance","roof","rookie","room","rose","rotate","rough","round","route","royal",
  "rubber","rude","rug","rule","run","runway","rural","sad","saddle","sadness",
  "safe","sail","salad","salmon","salon","salt","salute","same","sample","sand",
  "satisfy","satoshi","sauce","sausage","save","say","scale","scan","scare","scatter",
  "scene","scheme","school","science","scissors","scorpion","scout","scrap","screen","script",
  "scrub","sea","search","season","seat","second","secret","section","security","seed",
  "seek","segment","select","sell","seminar","senior","sense","sentence","series","service",
  "session","settle","setup","seven","shadow","shaft","shallow","share","shed","shell",
  "sheriff","shield","shift","shine","ship","shiver","shock","shoe","shoot","shop",
  "short","shoulder","shove","shrimp","shrug","shuffle","shy","sibling","sick","side",
  "siege","sight","sign","silent","silk","silly","silver","similar","simple","since",
  "sing","siren","sister","situate","six","size","skate","sketch","ski","skill",
  "skin","skirt","skull","slab","slam","sleep","slender","slice","slide","slight",
  "slim","slogan","slot","slow","slush","small","smart","smile","smoke","smooth",
  "snack","snake","snap","sniff","snow","soap","soccer","social","sock","soda",
  "soft","solar","soldier","solid","solution","solve","someone","song","soon","sorry",
  "sort","soul","sound","soup","source","south","space","spare","spatial","spawn",
  "speak","special","speed","spell","spend","sphere","spice","spider","spike","spin",
  "spirit","split","spoil","sponsor","spoon","sport","spot","spray","spread","spring",
  "spy","square","squeeze","squirrel","stable","stadium","staff","stage","stairs","stamp",
  "stand","start","state","stay","steak","steel","stem","step","stereo","stick",
  "still","sting","stock","stomach","stone","stool","story","stove","strategy","street",
  "strike","strong","struggle","student","stuff","stumble","style","subject","submit","subway",
  "success","such","sudden","suffer","sugar","suggest","suit","summer","sun","sunny",
  "sunset","super","supply","supreme","sure","surface","surge","surprise","surround","survey",
  "suspect","sustain","swallow","swamp","swap","swarm","swear","sweet","swift","swim",
  "swing","switch","sword","symbol","symptom","syrup","system","table","tackle","tag",
  "tail","talent","talk","tank","tape","target","task","taste","tattoo","taxi",
  "teach","team","tell","ten","tenant","tennis","tent","term","test","text",
  "thank","that","theme","then","theory","there","they","thing","this","thought",
  "three","thrive","throw","thumb","thunder","ticket","tide","tiger","tilt","timber",
  "time","tiny","tip","tired","tissue","title","toast","tobacco","today","toddler",
  "toe","together","toilet","token","tomato","tomorrow","tone","tongue","tonight","tool",
  "tooth","top","topic","topple","torch","tornado","tortoise","toss","total","tourist",
  "toward","tower","town","toy","track","trade","traffic","tragic","train","transfer",
  "trap","trash","travel","tray","treat","tree","trend","trial","tribe","trick",
  "trigger","trim","trip","trophy","trouble","truck","true","truly","trumpet","trust",
  "truth","try","tube","tuition","tumble","tuna","tunnel","turkey","turn","turtle",
  "twelve","twenty","twice","twin","twist","two","type","typical","ugly","umbrella",
  "unable","unaware","uncle","uncover","under","undo","unfair","unfold","unhappy","uniform",
  "unique","unit","universe","unknown","unlock","until","unusual","unveil","update","upgrade",
  "uphold","upon","upper","upset","urban","urge","usage","use","used","useful",
  "useless","usual","utility","vacant","vacuum","vague","valid","valley","valve","van",
  "vanish","vapor","various","vast","vault","vehicle","velvet","vendor","venture","venue",
  "verb","verify","version","very","vessel","veteran","viable","vibrant","vicious","victory",
  "video","view","village","vintage","violin","virtual","virus","visa","visit","visual",
  "vital","vivid","vocal","voice","void","volcano","volume","vote","voyage","wage",
  "wagon","wait","walk","wall","walnut","want","warfare","warm","warrior","wash",
  "wasp","waste","water","wave","way","wealth","weapon","wear","weasel","weather",
  "web","wedding","weekend","weird","welcome","west","wet","whale","what","wheat",
  "wheel","when","where","whip","whisper","wide","width","wife","wild","will",
  "win","window","wine","wing","wink","winner","winter","wire","wisdom","wise",
  "wish","witness","wolf","woman","wonder","wood","wool","word","work","world",
  "worry","worth","wrap","wreck","wrestle","wrist","write","wrong","yard","year",
  "yellow","you","young","youth","zebra","zero","zone","zoo"
];

const CryptoUtils = {

  // ============================
  // Constants
  // ============================
  _WRAP_VERSION: 0x02,
  _WRAP_EPHEM_LEN: 32,
  _WRAP_IV_LEN: 12,
  _WRAP_HEADER: 1 + 32 + 12,  // 45 bytes before ciphertext

  // ============================
  // Password-based key derivation
  // ============================

  /**
   * Check whether Argon2 runtime is available (e.g. argon2-browser).
   */
  isArgon2Available() {
    return !!(globalThis.argon2 && typeof globalThis.argon2.hash === "function");
  },

  /**
   * Derive 32 raw bytes from password using configured KDF.
   * Supports:
   *   - Argon2id (preferred when available and requested)
   *   - PBKDF2 (fallback / backward compatibility)
   * @returns {Promise<{raw: Uint8Array, kdf: object}>}
   */
  async deriveRawKeyFromPassword(password, saltBase64, opts = {}) {
    const saltU8 = new Uint8Array(this.base64ToArrayBuffer(saltBase64));
    const pass = String(password || "");
    if (!pass) throw new Error("Password is required");
    if (saltU8.byteLength < 16) throw new Error("KDF salt too short (minimum 16 bytes)");

    const requestedNameRaw = String(opts?.name || "").trim();
    const requestedName =
      /^argon2id$/i.test(requestedNameRaw) ? "Argon2id" :
      /^pbkdf2$/i.test(requestedNameRaw) ? "PBKDF2" :
      requestedNameRaw;
    const preferArgon2 = opts?.preferArgon2 !== false;
    const kdfName = requestedName || (preferArgon2 ? "Argon2id" : "PBKDF2");

    if (kdfName === "Argon2id") {
      if (!this.isArgon2Available()) {
        throw new Error("Argon2id runtime is not available in this client");
      } else {
        // Fail-closed: block derivation until the Argon2id self-test
        // (WASM integrity pin + KDF test vector) has completed successfully.
        // argon2-selftest.js sets globalThis.__argon2Ready=true on success,
        // false on failure. If the self-test promise is not exposed at all,
        // refuse to derive — we must not silently fall through.
        const selfTest = globalThis.__argon2SelfTest;
        if (!selfTest || typeof selfTest.then !== "function") {
          throw new Error("Argon2id self-test not initialized; refusing to derive");
        }
        try {
          await selfTest;
        } catch (_e) {
          throw new Error("Argon2id self-test failed; refusing to derive");
        }
        if (globalThis.__argon2Ready !== true) {
          throw new Error("Argon2id self-test did not pass; refusing to derive");
        }

        const t = Number(opts?.time_cost) > 0 ? Number(opts.time_cost) : 3;
        const m = Number(opts?.memory_kib) > 0 ? Number(opts.memory_kib) : 65536;
        const p = Number(opts?.parallelism) > 0 ? Number(opts.parallelism) : 1;
        const version = Number(opts?.version) > 0 ? Number(opts.version) : 19;

        if (t < 2) throw new Error(`Argon2id time_cost too low: ${t} (minimum 2)`);
        if (m < 32768) throw new Error(`Argon2id memory_kib too low: ${m} (minimum 32768)`);
        if (p < 1 || p > 8) throw new Error(`Argon2id parallelism out of range: ${p}`);

        const a2 = globalThis.argon2;
        const type = (a2.ArgonType && (a2.ArgonType.Argon2id ?? a2.ArgonType.ID))
          ?? a2.ARGON2ID
          ?? 2;

        const out = await a2.hash({
          pass,
          salt: saltU8,
          time: t,
          mem: m,
          parallelism: p,
          hashLen: 32,
          type,
          version,
          raw: true,
        });

        const rawOut = out?.hash instanceof Uint8Array ? out.hash : new Uint8Array(out?.hash || []);
        if (rawOut.byteLength !== 32) {
          throw new Error(`Argon2id output length is ${rawOut.byteLength}, expected 32`);
        }

        return {
          raw: rawOut,
          kdf: {
            name: "Argon2id",
            time_cost: t,
            memory_kib: m,
            parallelism: p,
            version,
          },
        };
      }
    }

    // PBKDF2 (fallback and legacy)
    const iterations =
      Number(opts?.iterations) > 0 ? Number(opts.iterations) : 620000;
    let hash = String(opts?.hash || "SHA-256").trim().toUpperCase();
    if (hash === "SHA256") hash = "SHA-256";
    if (hash === "SHA384") hash = "SHA-384";
    if (hash === "SHA512") hash = "SHA-512";

    const _MIN_ITER = 600_000;
    const _OK_HASHES = ["SHA-256", "SHA-384", "SHA-512"];
    if (iterations < _MIN_ITER)
      throw new Error(`KDF iterations too low: ${iterations} (minimum ${_MIN_ITER})`);
    if (!_OK_HASHES.includes(hash))
      throw new Error(`KDF hash not allowed: ${hash}`);

    const passwordBuffer = new TextEncoder().encode(pass);
    const keyMaterial = await crypto.subtle.importKey(
      "raw", passwordBuffer, "PBKDF2", false, ["deriveBits"]
    );
    const bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", salt: saltU8, iterations, hash },
      keyMaterial,
      256
    );

    return {
      raw: new Uint8Array(bits),
      kdf: { name: "PBKDF2", hash, iterations },
    };
  },

  /**
   * Derive AES-256 key from password (Argon2id preferred, PBKDF2 fallback).
   * @param {string} password
   * @param {string} saltBase64
   * @param {object} opts
   * @returns {Promise<CryptoKey>}
   */
  async deriveKeyFromPassword(password, saltBase64, opts = {}) {
    const { raw } = await this.deriveRawKeyFromPassword(password, saltBase64, opts);
    return crypto.subtle.importKey(
      "raw",
      raw,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  },

  // ============================
  // X25519 Identity Key â€” generate / export / import
  // ============================

  /**
   * Generate X25519 identity keypair.
   * @returns {Promise<CryptoKeyPair>} â€” { publicKey, privateKey }
   */
  async generateIdentityKeyPair() {
    return crypto.subtle.generateKey(
      { name: "X25519" },
      true,   // extractable (needed for export / backup)
      ["deriveBits"]
    );
  },

  /**
   * Export X25519 public key as base64 (32 raw bytes).
   */
  async exportPublicKey(publicKey) {
    const raw = await crypto.subtle.exportKey("raw", publicKey);
    return this.arrayBufferToBase64(raw);
  },

  /**
   * Export X25519 private key as base64 (PKCS8 DER).
   */
  async exportPrivateKey(privateKey) {
    const pkcs8 = await crypto.subtle.exportKey("pkcs8", privateKey);
    return this.arrayBufferToBase64(pkcs8);
  },

  /**
   * Import X25519 public key from base64 (32 raw bytes).
   * @param {string} base64
   * @returns {Promise<CryptoKey>}
   */
  async importPublicKey(base64) {
    const raw = this.base64ToArrayBuffer(base64);
    if (raw.byteLength !== 32) {
      throw new Error(
        `Invalid X25519 public key: expected 32 bytes, got ${raw.byteLength}. ` +
        `The peer may need to re-register to generate X25519 keys.`
      );
    }
    return crypto.subtle.importKey(
      "raw", raw, { name: "X25519" }, true, []
    );
  },

  /**
   * Import X25519 private key from base64 (PKCS8 DER).
   * @param {string} base64
   * @returns {Promise<CryptoKey>}
   */
  async importPrivateKey(base64) {
    const pkcs8 = this.base64ToArrayBuffer(base64);
    return crypto.subtle.importKey(
      "pkcs8", pkcs8, { name: "X25519" }, false, ["deriveBits"]
    );
  },

  /**
   * Canonical JSON stringify (stable key order) for AAD serialization.
   */
  _stableJson(value) {
    if (value === null || typeof value !== "object") return JSON.stringify(value);
    if (Array.isArray(value)) return `[${value.map((v) => this._stableJson(v)).join(",")}]`;
    const keys = Object.keys(value).sort();
    const parts = [];
    for (const k of keys) {
      const v = value[k];
      if (v === undefined) continue;
      parts.push(`${JSON.stringify(k)}:${this._stableJson(v)}`);
    }
    return `{${parts.join(",")}}`;
  },

  _normalizePrivateKeyKdfForAad(kdf) {
    const src = kdf || {};
    const name = String(src.name || "").trim();
    const out = { name };

    if (name === "Argon2id") {
      out.time_cost = Number(src.time_cost || 0);
      out.memory_kib = Number(src.memory_kib || 0);
      out.parallelism = Number(src.parallelism || 0);
      out.version = Number(src.version || 0);
      return out;
    }

    if (name === "PBKDF2") {
      out.hash = String(src.hash || "SHA-256");
      out.iterations = Number(src.iterations || 0);
      return out;
    }

    if (src.hash !== undefined) out.hash = String(src.hash);
    if (src.iterations !== undefined) out.iterations = Number(src.iterations || 0);
    if (src.time_cost !== undefined) out.time_cost = Number(src.time_cost || 0);
    if (src.memory_kib !== undefined) out.memory_kib = Number(src.memory_kib || 0);
    if (src.parallelism !== undefined) out.parallelism = Number(src.parallelism || 0);
    if (src.version !== undefined) out.version = Number(src.version || 0);
    return out;
  },

  /**
   * Build deterministic AAD string for key-container v3.
   */
  buildPrivateKeyContainerAAD(container) {
    const payload = {
      v: Number(container?.v || 0),
      alg: String(container?.alg || ""),
      username: String(container?.username || "").trim().toLowerCase(),
      ext_version: String(container?.ext_version || ""),
      created_at: Number(container?.created_at || 0),
      kdf: this._normalizePrivateKeyKdfForAad(container?.kdf),
    };
    return this._stableJson(payload);
  },

  /**
   * AES-GCM params for private-key container decrypt/encrypt.
   * v2: no AAD (legacy)
   * v3+: AAD is mandatory
   */
  buildPrivateKeyContainerGcmParams(container, ivBuffer) {
    const v = Number(container?.v || 0);
    if (v !== 3) throw new Error(`Unsupported private key container version: ${v}`);
    const params = { name: "AES-GCM", iv: ivBuffer };
    const aad = new TextEncoder().encode(this.buildPrivateKeyContainerAAD(container));
    params.additionalData = aad;
    return params;
  },

  /**
   * One-time migration helper: v2(no AAD) -> v3(with AAD) using already-derived AES key.
   * Keeps salt/kdf, replaces iv/ciphertext, and binds metadata via AAD.
   */
  async migrateLegacyPrivateKeyContainerV2ToV3WithAesKey(encrypted, aesKey, opts = {}) {
    const v = Number(encrypted?.v || 2);
    if (v === 3) return encrypted;
    if (v !== 2) throw new Error(`Unsupported legacy private key container version: ${v}`);
    if (!encrypted?.iv || !encrypted?.data || !encrypted?.salt || !encrypted?.kdf) {
      throw new Error("Malformed legacy private key container");
    }

    const legacyIv = this.base64ToArrayBuffer(encrypted.iv);
    const legacyData = this.base64ToArrayBuffer(encrypted.data);
    const decryptedBuffer = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: legacyIv }, aesKey, legacyData
    );
    const pkcs8B64 = new TextDecoder().decode(decryptedBuffer);

    let extVersion = "0";
    try {
      extVersion = String(opts?.extVersion || chrome?.runtime?.getManifest?.()?.version || "0");
    } catch {}
    const containerV3 = {
      v: 3,
      alg: "AES-256-GCM",
      kdf: encrypted.kdf,
      salt: encrypted.salt,
      iv: this.arrayBufferToBase64(crypto.getRandomValues(new Uint8Array(12))),
      created_at: Number(opts?.createdAt || Date.now()),
      username: String(opts?.username || "").trim().toLowerCase(),
      ext_version: extVersion,
    };
    const aad = new TextEncoder().encode(this.buildPrivateKeyContainerAAD(containerV3));
    const reIv = this.base64ToArrayBuffer(containerV3.iv);
    const reEncoded = new TextEncoder().encode(pkcs8B64);
    const reCipher = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: reIv, additionalData: aad },
      aesKey,
      reEncoded
    );

    return {
      ...containerV3,
      data: this.arrayBufferToBase64(reCipher),
    };
  },

  // ============================
  // Encrypted private key storage (password â†’ AES-GCM)
  // ============================

  /**
   * Decrypt user's private key from server blob + password.
   * @param {Object} encrypted â€” { salt, iv, data, kdf? }
   * @param {string} password
   * @returns {Promise<CryptoKey>}
   */
  async decryptPrivateKey(encrypted, password, opts = {}) {
    if (Number(encrypted?.v || 0) !== 3) {
      throw new Error("Legacy private key container is not supported (expected v3)");
    }
    const expectedUsername = String(opts?.expectedUsername || "").trim().toLowerCase();
    if (expectedUsername) {
      const actualUsername = String(encrypted?.username || "").trim().toLowerCase();
      if (!actualUsername || actualUsername !== expectedUsername) {
        throw new Error("Encrypted private key container username mismatch");
      }
    }
    const kdf = encrypted?.kdf || {};
    const aesKey = await this.deriveKeyFromPassword(password, encrypted.salt, {
      name: kdf.name,
      iterations: kdf.iterations,
      hash: kdf.hash,
      time_cost: kdf.time_cost,
      memory_kib: kdf.memory_kib,
      parallelism: kdf.parallelism,
      version: kdf.version,
      preferArgon2: true,
    });

    const iv = this.base64ToArrayBuffer(encrypted.iv);
    const encryptedData = this.base64ToArrayBuffer(encrypted.data);

    const decryptedBuffer = await crypto.subtle.decrypt(
      this.buildPrivateKeyContainerGcmParams(encrypted, iv), aesKey, encryptedData
    );

    // Decrypted payload is base64 of PKCS8 private key
    const pkcs8B64 = new TextDecoder().decode(decryptedBuffer);
    return this.importPrivateKey(pkcs8B64);
  },

  /**
   * Like decryptPrivateKey but returns the raw PKCS8 base64 string
   * instead of importing it as a CryptoKey. Used for password re-encryption.
   */
  async decryptPrivateKeyToPkcs8B64(encrypted, password, opts = {}) {
    if (Number(encrypted?.v || 0) !== 3) {
      throw new Error("Legacy private key container is not supported (expected v3)");
    }
    const expectedUsername = String(opts?.expectedUsername || "").trim().toLowerCase();
    if (expectedUsername) {
      const actualUsername = String(encrypted?.username || "").trim().toLowerCase();
      if (!actualUsername || actualUsername !== expectedUsername) {
        throw new Error("Encrypted private key container username mismatch");
      }
    }
    const kdf = encrypted?.kdf || {};
    const aesKey = await this.deriveKeyFromPassword(password, encrypted.salt, {
      name: kdf.name,
      iterations: kdf.iterations,
      hash: kdf.hash,
      time_cost: kdf.time_cost,
      memory_kib: kdf.memory_kib,
      parallelism: kdf.parallelism,
      version: kdf.version,
      preferArgon2: true,
    });

    const iv = this.base64ToArrayBuffer(encrypted.iv);
    const encryptedData = this.base64ToArrayBuffer(encrypted.data);

    const decryptedBuffer = await crypto.subtle.decrypt(
      this.buildPrivateKeyContainerGcmParams(encrypted, iv), aesKey, encryptedData
    );
    return new TextDecoder().decode(decryptedBuffer);
  },

  /**
   * Encrypt a PKCS8 private key (base64) with a password → v3 EPK container.
   * Mirrors login.js encryptPrivateKey for use in background.js password change.
   */
  async encryptPrivateKey(pkcs8B64, password, { username = "" } = {}) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const saltB64 = this.arrayBufferToBase64(salt);

    const derived = await this.deriveRawKeyFromPassword(password, saltB64, { preferArgon2: true });
    const aesKey = await crypto.subtle.importKey(
      "raw", derived.raw, { name: "AES-GCM", length: 256 }, false, ["encrypt"]
    );
    derived.raw.fill(0);

    const iv = crypto.getRandomValues(new Uint8Array(12));
    let extVersion = "0";
    try { extVersion = String(chrome?.runtime?.getManifest?.()?.version || "0"); } catch {}
    const container = {
      v: 3,
      alg: "AES-256-GCM",
      kdf: derived.kdf,
      salt: saltB64,
      iv: this.arrayBufferToBase64(iv),
      created_at: Date.now(),
      username: String(username || "").trim().toLowerCase(),
      ext_version: extVersion,
    };
    const aad = new TextEncoder().encode(this.buildPrivateKeyContainerAAD(container));
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: aad }, aesKey, new TextEncoder().encode(pkcs8B64)
    );
    return { ...container, data: this.arrayBufferToBase64(ciphertext) };
  },

  /**
   * Import raw 32-byte AES-GCM key (base64) as CryptoKey.
   * Used for one-shot session unlock (KEK).
   */
  async importAesKeyFromRaw(base64, extractable = false, usages = ["decrypt"]) {
    const raw = this.base64ToArrayBuffer(base64);
    return crypto.subtle.importKey(
      "raw", raw, { name: "AES-GCM", length: 256 }, !!extractable, usages
    );
  },

  /**
   * Decrypt user's private key using a pre-derived AES key (no password string).
   * @param {Object} encrypted â€” { salt, iv, data, kdf? }
   * @param {CryptoKey} aesKey
   * @returns {Promise<CryptoKey>}
   */
  async decryptPrivateKeyWithAesKey(encrypted, aesKey, opts = {}) {
    if (Number(encrypted?.v || 0) !== 3) {
      throw new Error("Legacy private key container is not supported (expected v3)");
    }
    const expectedUsername = String(opts?.expectedUsername || "").trim().toLowerCase();
    if (expectedUsername) {
      const actualUsername = String(encrypted?.username || "").trim().toLowerCase();
      if (!actualUsername || actualUsername !== expectedUsername) {
        throw new Error("Encrypted private key container username mismatch");
      }
    }
    const iv = this.base64ToArrayBuffer(encrypted.iv);
    const encryptedData = this.base64ToArrayBuffer(encrypted.data);

    const decryptedBuffer = await crypto.subtle.decrypt(
      this.buildPrivateKeyContainerGcmParams(encrypted, iv), aesKey, encryptedData
    );

    const pkcs8B64 = new TextDecoder().decode(decryptedBuffer);
    return this.importPrivateKey(pkcs8B64);
  },

  /**
   * Same as decryptPrivateKeyWithAesKey, but also derives the Ed25519 signing seed
   * from the raw X25519 private key bytes before importing them as non-extractable.
   * Returns { privateKey: CryptoKey, ed25519Seed: Uint8Array }.
   * The raw key bytes are wiped after derivation.
   */
  async decryptPrivateKeyWithAesKeyAll(encrypted, aesKey, opts = {}) {
    if (Number(encrypted?.v || 0) !== 3) {
      throw new Error("Legacy private key container is not supported (expected v3)");
    }
    const expectedUsername = String(opts?.expectedUsername || "").trim().toLowerCase();
    if (expectedUsername) {
      const actualUsername = String(encrypted?.username || "").trim().toLowerCase();
      if (!actualUsername || actualUsername !== expectedUsername) {
        throw new Error("Encrypted private key container username mismatch");
      }
    }
    const iv = this.base64ToArrayBuffer(encrypted.iv);
    const encryptedData = this.base64ToArrayBuffer(encrypted.data);

    const decryptedBuffer = await crypto.subtle.decrypt(
      this.buildPrivateKeyContainerGcmParams(encrypted, iv), aesKey, encryptedData
    );

    const pkcs8B64 = new TextDecoder().decode(decryptedBuffer);
    const pkcs8Bytes = new Uint8Array(this.base64ToArrayBuffer(pkcs8B64));
    const rawBytes = this.extractRawKeyFromPkcs8(pkcs8Bytes);

    const ed25519Seed = await this.deriveEd25519Seed(rawBytes);
    rawBytes.fill(0); // wipe raw key bytes from memory

    const privateKey = await this.importPrivateKey(pkcs8B64);
    return { privateKey, ed25519Seed };
  },

  // ============================
  // Room key generation / import / export (AES-256-GCM, unchanged)
  // ============================

  async generateRoomKey(exportable = false) {
    return crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      !!exportable,
      ["encrypt", "decrypt"]
    );
  },

  async exportRoomKey(key) {
    const exported = await crypto.subtle.exportKey("raw", key);
    return this.arrayBufferToBase64(exported);
  },

  async importRoomKey(base64) {
    const raw = this.base64ToArrayBuffer(base64);
    return crypto.subtle.importKey(
      "raw", raw, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
    );
  },

  async importRoomKeyExportable(base64) {
    const raw = this.base64ToArrayBuffer(base64);
    return crypto.subtle.importKey(
      "raw", raw, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]
    );
  },

  /**
   * Fingerprint a room key (first 8 bytes of SHA-256 â†’ 16 hex chars).
   */
  async fingerprintRoomKeyBase64(base64) {
    const raw = this.base64ToArrayBuffer(base64);
    const hash = await crypto.subtle.digest("SHA-256", raw);
    const arr = new Uint8Array(hash);
    let hex = "";
    for (let i = 0; i < 8; i++) hex += arr[i].toString(16).padStart(2, "0");
    return hex;
  },

  // ============================
  // X25519 ECDH key wrapping / unwrapping
  // ============================
  //
  // Replaces RSA-OAEP encrypt/decrypt for room key sharing.
  //
  // Wrap:
  //   1. Generate ephemeral X25519 keypair
  //   2. ECDH(ephemeral_priv, peer_pub) â†’ shared secret (32 bytes)
  //   3. HKDF(shared_secret, salt=ephemeral_pub, info="ws-e2ee-wrap-v2") â†’ AES-256 key
  //   4. AES-GCM encrypt(wrapping_key, room_key_bytes)
  //   5. Output: version || ephemeral_pub || iv || ciphertext
  //
  // Unwrap:
  //   1. Parse ephemeral_pub, iv, ciphertext from blob
  //   2. ECDH(my_priv, ephemeral_pub) â†’ shared secret
  //   3. HKDF(shared_secret, salt=ephemeral_pub, info="ws-e2ee-wrap-v2") â†’ AES-256 key
  //   4. AES-GCM decrypt â†’ room key bytes

  /**
   * Derive AES wrapping key from ECDH shared secret + ephemeral public key.
   * @param {ArrayBuffer} sharedBits â€” 256-bit ECDH output
   * @param {Uint8Array}  ephemeralPubRaw â€” 32-byte ephemeral public key (used as HKDF salt)
   * @returns {Promise<CryptoKey>} â€” AES-256-GCM key
   */
  async _deriveWrappingKey(sharedBits, ephemeralPubRaw) {
    const hkdfKey = await crypto.subtle.importKey(
      "raw", sharedBits, "HKDF", false, ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: ephemeralPubRaw,
        info: new TextEncoder().encode("ws-e2ee-wrap-v2"),
      },
      hkdfKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  },

  /**
   * Wrap (encrypt) a room/thread key for a specific user.
   * Uses ephemeral X25519 ECDH + HKDF + AES-GCM.
   *
   * @param {string} peerPublicKeyBase64 â€” recipient's X25519 public key (32 bytes, base64)
   * @param {string} roomKeyBase64       â€” raw AES room key (32 bytes, base64)
   * @returns {Promise<string>}          â€” wrapped blob (base64)
   */
  async encryptRoomKeyForUser(peerPublicKeyBase64, roomKeyBase64) {
    // 1. Import peer's static public key
    const peerPub = await this.importPublicKey(peerPublicKeyBase64);

    // 2. Generate ephemeral X25519 keypair
    const ephemeral = await crypto.subtle.generateKey(
      { name: "X25519" }, true, ["deriveBits"]
    );

    // 3. ECDH: ephemeral_priv Ã— peer_pub â†’ shared secret
    const sharedBits = await crypto.subtle.deriveBits(
      { name: "X25519", public: peerPub },
      ephemeral.privateKey,
      256
    );

    // 4. Export ephemeral public key (32 bytes)
    const ephemPubRaw = new Uint8Array(
      await crypto.subtle.exportKey("raw", ephemeral.publicKey)
    );

    // 5. HKDF â†’ AES wrapping key
    const wrappingKey = await this._deriveWrappingKey(sharedBits, ephemPubRaw);

    // 6. AES-GCM encrypt the room key
    const iv = crypto.getRandomValues(new Uint8Array(this._WRAP_IV_LEN));
    const roomKeyBytes = this.base64ToArrayBuffer(roomKeyBase64);

    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      wrappingKey,
      roomKeyBytes
    );

    // 7. Assemble blob: version || ephemeral_pub || iv || ciphertext
    const ctBytes = new Uint8Array(ciphertext);
    const blob = new Uint8Array(this._WRAP_HEADER + ctBytes.length);
    blob[0] = this._WRAP_VERSION;
    blob.set(ephemPubRaw, 1);
    blob.set(iv, 1 + this._WRAP_EPHEM_LEN);
    blob.set(ctBytes, this._WRAP_HEADER);

    return this.arrayBufferToBase64(blob.buffer);
  },

  /**
   * Unwrap (decrypt) a room/thread key wrapped for us.
   *
   * @param {CryptoKey} privateKey        â€” our X25519 private key
   * @param {string}    encryptedBase64   â€” wrapped blob (base64)
   * @returns {Promise<string>}           â€” raw AES room key (base64)
   */
  async decryptRoomKeyForUser(privateKey, encryptedBase64) {
    const blob = new Uint8Array(this.base64ToArrayBuffer(encryptedBase64));

    // Validate version
    if (blob.length < this._WRAP_HEADER + 1 || blob[0] !== this._WRAP_VERSION) {
      throw new Error("Unsupported wrapped key format (expected v2 X25519)");
    }

    // Parse components
    const ephemPubRaw = blob.slice(1, 1 + this._WRAP_EPHEM_LEN);
    const iv = blob.slice(1 + this._WRAP_EPHEM_LEN, this._WRAP_HEADER);
    const ciphertext = blob.slice(this._WRAP_HEADER);

    // Import ephemeral public key
    const ephemPub = await crypto.subtle.importKey(
      "raw", ephemPubRaw, { name: "X25519" }, false, []
    );

    // ECDH: my_priv Ã— ephemeral_pub â†’ shared secret
    const sharedBits = await crypto.subtle.deriveBits(
      { name: "X25519", public: ephemPub },
      privateKey,
      256
    );

    // HKDF â†’ AES unwrapping key
    const unwrappingKey = await this._deriveWrappingKey(sharedBits, ephemPubRaw);

    // AES-GCM decrypt
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      unwrappingKey,
      ciphertext
    );

    return this.arrayBufferToBase64(plaintext);
  },

// ============================
// Safety Numbers (fingerprints)
// ============================
//
// Computes a "safety number" for a pair of users â€” similar to Signal.
// Both users see the SAME number for the same pair.
// If the server swaps a public key (MITM), the number changes.
//
// Algorithm:
//   1. Sort the two identifiers lexicographically (Aâ†’B == Bâ†’A)
//   2. SHA-256( sorted_id_1 + "|" + pubkey_1 + "||" + sorted_id_2 + "|" + pubkey_2 )
//   3. Take the first 30 bytes of the hash â†’ 60 decimal digits, grouped by 5
//
// Format: "12345 67890 12345 67890 12345 67890 12345 67890 12345 67890 12345 67890"

  /**
   * Compute safety number for a pair of users.
   * @param {string} myUsername
   * @param {string} myPublicKeyB64   â€” base64 raw X25519 public key
   * @param {string} peerUsername
   * @param {string} peerPublicKeyB64 â€” base64 raw X25519 public key
   * @returns {Promise<string>} 60-digit safety number "12345 67890 ..."
   */
  async computeSafetyNumber(myUsername, myPublicKeyB64, peerUsername, peerPublicKeyB64) {
    const normKey = (b64) => String(b64 || "").trim();
    const idA = String(myUsername || "").toLowerCase();
    const idB = String(peerUsername || "").toLowerCase();
    const keyA = normKey(myPublicKeyB64);
    const keyB = normKey(peerPublicKeyB64);

    // Sort lexicographically so both sides get the same result
    let first, second;
    if (idA < idB) {
      first = idA + "|" + keyA;
      second = idB + "|" + keyB;
    } else if (idA > idB) {
      first = idB + "|" + keyB;
      second = idA + "|" + keyA;
    } else {
      // Same user (shouldn't happen) â€” sort by key
      first = idA + "|" + (keyA < keyB ? keyA : keyB);
      second = idB + "|" + (keyA < keyB ? keyB : keyA);
    }

    const payload = first + "||" + second;
    const hashBuf = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(payload)
    );
    const hashBytes = new Uint8Array(hashBuf);

    // First 30 bytes â†’ 60 decimal digits
    // Bug fix: previous byte-by-byte .padStart(2,"0").slice(-2) dropped the
    // leading digit for bytes ≥ 100, causing ~60% of values to collide and
    // reducing effective entropy from 240 to ~199 bits.
    // Fix: treat 30 bytes as one BigInt → decimal string (no collisions).
    let n = 0n;
    for (let i = 0; i < 30; i++) {
      n = n * 256n + BigInt(hashBytes[i]);
    }
    // 2^240 fits in at most 73 decimal digits; pad and take the first 60.
    const dec = n.toString(10).padStart(73, "0").slice(0, 60);
    const groups = [];
    for (let i = 0; i < 60; i += 5) {
      groups.push(dec.slice(i, i + 5));
    }
    return groups.join(" ");
  },

  /**
   * Fingerprint a public key (first 16 bytes of SHA-256 → 32 hex chars).
   * Hashes the RAW 32-byte X25519 public key (base64-decoded), not the
   * base64 text. Whitespace / padding variants in the encoding no longer
   * influence the fingerprint, and the fingerprint is canonical w.r.t.
   * the actual key material.
   * @param {string} publicKeyB64 — base64 raw X25519 public key
   * @returns {Promise<string>}
   */
  async fingerprintPublicKey(publicKeyB64) {
    const normalized = String(publicKeyB64 || "").trim();
    const rawBytes = new Uint8Array(this.base64ToArrayBuffer(normalized));
    const hash = await crypto.subtle.digest("SHA-256", rawBytes);
    const arr = new Uint8Array(hash);
    let hex = "";
    for (let i = 0; i < 16; i++) {
      hex += arr[i].toString(16).padStart(2, "0");
    }
    return hex;
  },

  /**
   * LEGACY fingerprint: hashes UTF-8 bytes of the base64 text (bugged).
   * Kept ONLY so callers can detect and silently migrate values stored
   * under the old format. Never use for new comparisons.
   * @param {string} publicKeyB64
   * @returns {Promise<string>}
   */
  async _fingerprintPublicKeyLegacy(publicKeyB64) {
    const normalized = String(publicKeyB64 || "").trim();
    const bytes = new TextEncoder().encode(normalized);
    const hash = await crypto.subtle.digest("SHA-256", bytes);
    const arr = new Uint8Array(hash);
    let hex = "";
    for (let i = 0; i < 16; i++) {
      hex += arr[i].toString(16).padStart(2, "0");
    }
    return hex;
  },

  // ============================
  // Message padding (v1) â€” unchanged
  // ============================

  _PAD_HEADER: 5,
  _PAD_VERSION: 0x01,
  _PAD_MIN_BUCKET: 64,

  _padBucket(totalBytes) {
    let bucket = this._PAD_MIN_BUCKET;
    while (bucket < totalBytes) bucket *= 2;
    return bucket;
  },

  _padPlaintext(msgBytes) {
    const msgLen = msgBytes.byteLength;
    const needed = this._PAD_HEADER + msgLen;
    const bucket = this._padBucket(needed);
    const padded = new Uint8Array(bucket);
    crypto.getRandomValues(padded);
    padded[0] = this._PAD_VERSION;
    padded[1] = (msgLen >>> 24) & 0xff;
    padded[2] = (msgLen >>> 16) & 0xff;
    padded[3] = (msgLen >>>  8) & 0xff;
    padded[4] =  msgLen         & 0xff;
    padded.set(msgBytes, this._PAD_HEADER);
    return padded;
  },

  _unpadPlaintext(decryptedBuf) {
    const bytes = new Uint8Array(decryptedBuf);
    if (bytes.length < this._PAD_HEADER || bytes[0] !== this._PAD_VERSION) {
      return new TextDecoder().decode(decryptedBuf);
    }
    const msgLen =
      (bytes[1] << 24) | (bytes[2] << 16) | (bytes[3] << 8) | bytes[4];
    if (msgLen < 0 || this._PAD_HEADER + msgLen > bytes.length) {
      throw new Error("Invalid padded message: length out of bounds");
    }
    return new TextDecoder().decode(
      bytes.subarray(this._PAD_HEADER, this._PAD_HEADER + msgLen)
    );
  },

  // ============================
  // Message encrypt / decrypt (AES-GCM, unchanged)
  // ============================

  async encryptMessage(roomKey, plaintext, additionalData) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const msgBytes = new TextEncoder().encode(plaintext);
    const padded = this._padPlaintext(msgBytes);
    const params = { name: "AES-GCM", iv };
    if (additionalData) params.additionalData = additionalData;
    const ciphertext = await crypto.subtle.encrypt(params, roomKey, padded);
    return {
      iv: this.arrayBufferToBase64(iv),
      data: this.arrayBufferToBase64(ciphertext),
    };
  },

  async decryptMessage(roomKey, encrypted, additionalData) {
    const iv = this.base64ToArrayBuffer(encrypted.iv);
    const ciphertext = this.base64ToArrayBuffer(encrypted.data);
    const params = { name: "AES-GCM", iv };
    if (additionalData) params.additionalData = additionalData;
    const decrypted = await crypto.subtle.decrypt(params, roomKey, ciphertext);
    return this._unpadPlaintext(decrypted);
  },

  // ============================
  // Helpers
  // ============================

  arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  },

  base64ToArrayBuffer(base64) {
    let b64 = String(base64 || "").replace(/-/g, "+").replace(/_/g, "/").trim();
    const pad = b64.length % 4;
    if (pad) b64 += "=".repeat(4 - pad);
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  },

  // ─── BIP39 / Recovery helpers ──────────────────────────────────────────────

  // PKCS8 X25519 fixed header (16 bytes): OID 1.3.101.110 + SEQUENCE wrapper
  _PKCS8_X25519_HEADER: new Uint8Array([
    0x30,0x2e,0x02,0x01,0x00,0x30,0x05,0x06,0x03,0x2b,0x65,0x6e,0x04,0x22,0x04,0x20
  ]),

  // PKCS8 Ed25519 fixed header (16 bytes): OID 1.3.101.112 + SEQUENCE wrapper
  _PKCS8_ED25519_HEADER: new Uint8Array([
    0x30,0x2e,0x02,0x01,0x00,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x04,0x22,0x04,0x20
  ]),

  /** Extract the 32-byte raw private key from a 48-byte X25519 PKCS8 blob. */
  extractRawKeyFromPkcs8(pkcs8Bytes) {
    const b = pkcs8Bytes instanceof Uint8Array ? pkcs8Bytes : new Uint8Array(pkcs8Bytes);
    if (b.length !== 48) throw new Error(`PKCS8 length ${b.length} != 48`);
    return b.slice(16, 48);
  },

  /** Reconstruct a 48-byte X25519 PKCS8 blob from 32 raw key bytes. */
  buildPkcs8FromRawKey(rawBytes) {
    const raw = rawBytes instanceof Uint8Array ? rawBytes : new Uint8Array(rawBytes);
    if (raw.length !== 32) throw new Error(`Raw key length ${raw.length} != 32`);
    const out = new Uint8Array(48);
    out.set(this._PKCS8_X25519_HEADER, 0);
    out.set(raw, 16);
    return out;
  },

  /**
   * Encode 32 raw bytes as a 24-word BIP39 mnemonic.
   * 256-bit entropy + 8-bit SHA-256 checksum = 264 bits → 24 × 11-bit words.
   */
  bip39Encode(rawBytes) {
    const b = rawBytes instanceof Uint8Array ? rawBytes : new Uint8Array(rawBytes);
    if (b.length !== 32) throw new Error(`bip39Encode: expected 32 bytes, got ${b.length}`);

    // Compute SHA-256 checksum (synchronous via _sha256Sync not available — use inline)
    // We use the synchronous CryptoUtils._sha256SyncBytes helper below.
    // Because WebCrypto is async, we pre-compute checksum using a manual SHA-256.
    const checkByte = this._sha256FirstByte(b);

    // Build 264-bit number as BigInt: 256 bits of entropy + 8 bits of checksum
    let bits = BigInt(0);
    for (const byte of b) bits = (bits << 8n) | BigInt(byte);
    bits = (bits << 8n) | BigInt(checkByte);

    // Extract 24 groups of 11 bits (right to left)
    const words = [];
    for (let i = 0; i < 24; i++) {
      words.unshift(_BIP39_WORDLIST[Number(bits & 0x7ffn)]);
      bits >>= 11n;
    }
    return words.join(" ");
  },

  /**
   * Decode a 24-word BIP39 mnemonic back to 32 raw bytes.
   * Throws if word count is wrong, any word is unknown, or checksum fails.
   */
  bip39Decode(phrase) {
    const words = String(phrase || "").trim().toLowerCase().split(/\s+/);
    if (words.length !== 24) throw new Error(`Expected 24 words, got ${words.length}`);

    // Rebuild 264-bit BigInt
    let bits = BigInt(0);
    for (const w of words) {
      const idx = _BIP39_WORDLIST.indexOf(w);
      if (idx === -1) throw new Error(`Unknown BIP39 word: "${w}"`);
      bits = (bits << 11n) | BigInt(idx);
    }

    // Split: high 256 bits = entropy, low 8 bits = checksum
    const checksumByte = Number(bits & 0xffn);
    bits >>= 8n;

    const raw = new Uint8Array(32);
    for (let i = 31; i >= 0; i--) {
      raw[i] = Number(bits & 0xffn);
      bits >>= 8n;
    }

    // Verify checksum
    const expected = this._sha256FirstByte(raw);
    if (checksumByte !== expected) throw new Error("BIP39 checksum mismatch — phrase is incorrect");

    return raw;
  },

  /**
   * Compute SHA-256 of bytes synchronously and return the first byte.
   * Uses a minimal pure-JS SHA-256 so bip39Encode/Decode stay synchronous.
   */
  _sha256FirstByte(data) {
    // Pure-JS SHA-256 (FIPS 180-4)
    const K = [
      0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
      0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
      0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
      0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
      0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
      0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
      0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
      0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    ];
    let h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a,
        h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;

    // Pre-process: pad message
    const msgLen = data.length;
    const bitLen = msgLen * 8;
    const padLen = ((msgLen + 9 + 63) & ~63);
    const padded = new Uint8Array(padLen);
    padded.set(data);
    padded[msgLen] = 0x80;
    const dv = new DataView(padded.buffer);
    dv.setUint32(padLen - 4, bitLen >>> 0, false);
    dv.setUint32(padLen - 8, Math.floor(bitLen / 0x100000000) >>> 0, false);

    const rotr = (x, n) => (x >>> n) | (x << (32 - n));

    for (let off = 0; off < padLen; off += 64) {
      const w = new Uint32Array(64);
      for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4, false);
      for (let i = 16; i < 64; i++) {
        const s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15]>>>3);
        const s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19)  ^ (w[i-2]>>>10);
        w[i] = (w[i-16] + s0 + w[i-7] + s1) >>> 0;
      }
      let [a,b,c,d,e,f,g,h] = [h0,h1,h2,h3,h4,h5,h6,h7];
      for (let i = 0; i < 64; i++) {
        const S1  = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
        const ch  = (e & f) ^ (~e & g);
        const tmp1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
        const S0  = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const tmp2 = (S0 + maj) >>> 0;
        [h,g,f,e,d,c,b,a] = [g,f,e,(d+tmp1)>>>0,c,b,a,(tmp1+tmp2)>>>0];
      }
      h0=(h0+a)>>>0; h1=(h1+b)>>>0; h2=(h2+c)>>>0; h3=(h3+d)>>>0;
      h4=(h4+e)>>>0; h5=(h5+f)>>>0; h6=(h6+g)>>>0; h7=(h7+h)>>>0;
    }
    return h0 >>> 24; // first byte of hash
  },

  /**
   * Derive a 32-byte recovery auth token from raw X25519 private key bytes.
   * recovery_auth = HKDF-SHA256(ikm=rawKey, salt=0x00*32, info="ws-messenger-recovery-v1")
   */
  async deriveRecoveryAuth(rawKeyBytes) {
    const raw = rawKeyBytes instanceof Uint8Array ? rawKeyBytes : new Uint8Array(rawKeyBytes);
    const ikm = await crypto.subtle.importKey("raw", raw, "HKDF", false, ["deriveBits"]);
    const info = new TextEncoder().encode("ws-messenger-recovery-v1");
    const salt = new Uint8Array(32); // zero salt
    const bits = await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt, info },
      ikm,
      256
    );
    return new Uint8Array(bits);
  },

  /** SHA-256 of bytes → hex string (async, uses WebCrypto). */
  async sha256Hex(bytes) {
    const buf = await crypto.subtle.digest("SHA-256", bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes));
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
  },

  /** SHA-256 of bytes → Uint8Array (async, uses WebCrypto). */
  async sha256Raw(bytes) {
    const buf = await crypto.subtle.digest("SHA-256", bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes));
    return new Uint8Array(buf);
  },

  // ============================
  // Ed25519 signing (sealed-sender DM envelope authentication)
  // ============================

  /**
   * Derive a 32-byte Ed25519 signing seed from an X25519 private key.
   * HKDF-SHA256(ikm=x25519PrivRaw, salt=0x00*32, info="ws-id-signing-v1")
   * Deterministic — no new key material needed.
   */
  async deriveEd25519Seed(x25519PrivRaw) {
    const raw = x25519PrivRaw instanceof Uint8Array ? x25519PrivRaw : new Uint8Array(x25519PrivRaw);
    const ikm = await crypto.subtle.importKey("raw", raw, "HKDF", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: new TextEncoder().encode("ws-id-signing-v1") },
      ikm, 256
    );
    return new Uint8Array(bits);
  },

  /**
   * Derive Ed25519 public key (32 bytes) from a 32-byte seed.
   * Wraps seed in PKCS8, imports as private key, exports JWK to read x (public key).
   * Requires extractable: true for the import.
   */
  async ed25519GetPublicKey(seed) {
    const s = seed instanceof Uint8Array ? seed : new Uint8Array(seed);
    const pkcs8 = new Uint8Array(48);
    pkcs8.set(this._PKCS8_ED25519_HEADER, 0);
    pkcs8.set(s, 16);
    const privKey = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, true, ["sign"]);
    const jwk = await crypto.subtle.exportKey("jwk", privKey);
    // JWK x field = base64url-encoded 32-byte public key (RFC 8037)
    return new Uint8Array(this.base64ToArrayBuffer(jwk.x));
  },

  /**
   * Canonical byte representation of a DM message for signing.
   * Format: [12b "ws-dm-sig-v1"][4b threadId BE uint32][2b from_len BE uint16][from utf8][body utf8]
   * Must match the Android CryptoUtils._dmSigMessage() format exactly.
   */
  _dmSigMessage(threadId, from, body) {
    const prefix   = new TextEncoder().encode("ws-dm-sig-v1"); // 12 bytes
    const fromBytes = new TextEncoder().encode(String(from || ""));
    const bodyBytes = new TextEncoder().encode(String(body || ""));
    const tidNum   = (parseInt(threadId, 10) >>> 0);
    const buf = new Uint8Array(12 + 4 + 2 + fromBytes.length + bodyBytes.length);
    const dv  = new DataView(buf.buffer);
    let off = 0;
    buf.set(prefix, off);           off += 12;
    dv.setUint32(off, tidNum, false); off += 4;  // big-endian
    dv.setUint16(off, fromBytes.length, false); off += 2;  // big-endian
    buf.set(fromBytes, off);        off += fromBytes.length;
    buf.set(bodyBytes, off);
    return buf;
  },

  /**
   * Sign msgBytes with Ed25519 seed. Returns base64url-encoded 64-byte signature.
   */
  async ed25519Sign(seed, msgBytes) {
    const s = seed instanceof Uint8Array ? seed : new Uint8Array(seed);
    const pkcs8 = new Uint8Array(48);
    pkcs8.set(this._PKCS8_ED25519_HEADER, 0);
    pkcs8.set(s, 16);
    const privKey = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, ["sign"]);
    const sig = await crypto.subtle.sign("Ed25519", privKey, msgBytes);
    return this.arrayBufferToBase64(sig).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  },

  /**
   * Verify an Ed25519 signature.
   * @param {Uint8Array} pubKeyBytes — 32-byte raw public key
   * @param {Uint8Array} sigBytes   — 64-byte signature
   * @param {Uint8Array} msgBytes   — signed message bytes
   * @returns {Promise<boolean>}
   */
  async ed25519Verify(pubKeyBytes, sigBytes, msgBytes) {
    const pub = pubKeyBytes instanceof Uint8Array ? pubKeyBytes : new Uint8Array(pubKeyBytes);
    const pubKey = await crypto.subtle.importKey("raw", pub, { name: "Ed25519" }, false, ["verify"]);
    return crypto.subtle.verify("Ed25519", pubKey, sigBytes, msgBytes);
  },
};

// Expose as frozen, non-patchable
(() => {
  const g = globalThis;
  const root = (g.__wsCrypto = g.__wsCrypto || {});
  const utils = Object.freeze(CryptoUtils);
  Object.defineProperty(root, "utils", {
    value: utils,
    writable: false,
    configurable: false,
    enumerable: false,
  });
})();
