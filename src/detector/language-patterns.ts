/**
 * Language-Agnostic Security Analysis Patterns
 *
 * Defines security patterns for different programming languages to enable
 * universal vulnerability detection across codebases.
 */

export type Language = 'cpp' | 'c' | 'javascript' | 'typescript' | 'python' | 'go' | 'rust' | 'java' | 'csharp' | 'php' | 'ruby' | 'unknown';

export interface LanguagePatterns {
  // Execution context patterns
  compilerCode: RegExp[];          // Code that runs at compile/build time
  runtimeCode: RegExp[];           // Code that runs in production
  startupCode: RegExp[];           // Code that runs once at initialization
  testCode: RegExp[];              // Test/development code

  // Function type patterns
  outputFunctions: RegExp[];       // Functions that WRITE/GENERATE (not parse)
  inputFunctions: RegExp[];        // Functions that READ/PARSE
  validationFunctions: RegExp[];   // Functions that CHECK/VALIDATE

  // Trust boundary patterns
  embedderAPIs: RegExp[];          // Internal/trusted APIs
  externalAPIs: RegExp[];          // Public/untrusted entry points

  // Threading patterns
  singleThreaded: boolean;         // Language is single-threaded by default
  concurrencyKeywords: RegExp[];   // Keywords indicating actual concurrency

  // Memory safety patterns
  memoryUnsafe: boolean;           // Language allows manual memory management
  unsafeOperations: RegExp[];      // Potentially unsafe operations
  safetyChecks: RegExp[];          // Built-in safety mechanisms

  // Attacker entry points
  userInputAPIs: RegExp[];         // APIs that accept external input
  deserializationAPIs: RegExp[];   // Parsing/deserialization entry points
}

export const LANGUAGE_PATTERNS: Record<Language, LanguagePatterns> = {
  cpp: {
    compilerCode: [
      /BytecodeGenerator|CodeGenerator|AstBuilder|Parser|Compiler/i,
      /\/codegen\/|\/compiler\/|\/ast\/|\/parsing\//,
      /Generate.*Code|Emit.*Bytecode|Compile/i
    ],
    runtimeCode: [
      /Runtime_|Builtin_|\/runtime\/|\/builtins\/|\/execution\//,
      /Execute|Invoke|Call|Apply/i
    ],
    startupCode: [
      /Snapshot|Deserialize|Initialization|Bootstrap|Startup/i,
      /\/snapshot\/|\/init\//
    ],
    testCode: [
      /\/test\/|\/tests\/|\/cctest\/|\/unittests\/|_test\.cc$|_unittest\.cc$/
    ],
    outputFunctions: [
      /^(write_|Write|Emit|Generate|Serialize|Output|Print|Format)/i
    ],
    inputFunctions: [
      /^(read_|Read|Parse|Deserialize|Load|Extract|Decode)/i
    ],
    validationFunctions: [
      /^(Check|Validate|Verify|Assert|Ensure|DCHECK|CHECK)/i
    ],
    embedderAPIs: [
      /^v8::|^api::|Extension|Inspector|Embedder/i,
      /\/api\/|\/extensions\/|\/inspector\//
    ],
    externalAPIs: [
      /HttpRequest|Socket|FileInput|stdin|argv|environ/i
    ],
    singleThreaded: false,
    concurrencyKeywords: [
      /std::thread|pthread|std::mutex|std::atomic|concurrent|parallel/i,
      /SharedArrayBuffer|Atomics/
    ],
    memoryUnsafe: true,
    unsafeOperations: [
      /\b(malloc|free|new|delete|memcpy|strcpy|strcat|sprintf)\b/,
      /reinterpret_cast|static_cast|const_cast/
    ],
    safetyChecks: [
      /std::unique_ptr|std::shared_ptr|std::vector|std::string/,
      /CHECK|DCHECK|assert/i
    ],
    userInputAPIs: [
      /recv|read|fread|getline|scanf|gets|ReadFile/i
    ],
    deserializationAPIs: [
      /Deserialize|Parse|Decode|Unmarshal|fromJSON|fromXML/i
    ]
  },

  c: {
    compilerCode: [/lex|yacc|parse|compile/i],
    runtimeCode: [/main|execute|run/i],
    startupCode: [/init|setup|bootstrap/i],
    testCode: [/\/test\/|_test\.c$|\/tests\//],
    outputFunctions: [/^(write|fprintf|sprintf|snprintf|printf)/i],
    inputFunctions: [/^(read|scanf|fscanf|fgets|gets|getline)/i],
    validationFunctions: [/^(check|validate|assert)/i],
    embedderAPIs: [/^_|^__/], // Internal functions
    externalAPIs: [/socket|accept|recv|read|fopen/i],
    singleThreaded: false,
    concurrencyKeywords: [/pthread|fork|thread/i],
    memoryUnsafe: true,
    unsafeOperations: [
      /\b(malloc|calloc|realloc|free|memcpy|strcpy|strcat|sprintf|gets)\b/
    ],
    safetyChecks: [/assert|if\s*\([^)]*NULL\)/],
    userInputAPIs: [/recv|read|fread|getline|scanf|gets/i],
    deserializationAPIs: [/parse|decode|unmarshal/i]
  },

  javascript: {
    compilerCode: [/babel|webpack|compiler|transpile/i],
    runtimeCode: [/\.js$|\/src\/|\/lib\//],
    startupCode: [/init|setup|bootstrap|main/i],
    testCode: [/\.test\.|\.spec\.|\/test\/|\/tests\/|__tests__/],
    outputFunctions: [/^(write|send|emit|render|serialize)/i],
    inputFunctions: [/^(read|parse|decode|deserialize|extract)/i],
    validationFunctions: [/^(validate|check|verify|assert|ensure)/i],
    embedderAPIs: [/^process\.|^__/],
    externalAPIs: [
      /fetch|XMLHttpRequest|req\.|request\.|socket|postMessage/i
    ],
    singleThreaded: true,
    concurrencyKeywords: [/Worker|SharedArrayBuffer|Atomics/],
    memoryUnsafe: false,
    unsafeOperations: [/eval|Function\(|new Function|vm\.runInContext/],
    safetyChecks: [/typeof|instanceof|Array\.isArray/],
    userInputAPIs: [
      /req\.|request\.|body|query|params|headers|cookies/i,
      /fetch|XMLHttpRequest|postMessage/i
    ],
    deserializationAPIs: [/JSON\.parse|eval|deserialize|decode/i]
  },

  typescript: {
    compilerCode: [/tsc|compiler|transformer/i],
    runtimeCode: [/\.ts$|\/src\/|\/lib\//],
    startupCode: [/init|setup|bootstrap|main/i],
    testCode: [/\.test\.|\.spec\.|\/test\/|\/tests\/|__tests__/],
    outputFunctions: [/^(write|send|emit|render|serialize)/i],
    inputFunctions: [/^(read|parse|decode|deserialize|extract)/i],
    validationFunctions: [/^(validate|check|verify|assert|ensure)/i],
    embedderAPIs: [/^process\.|^__/],
    externalAPIs: [
      /fetch|XMLHttpRequest|req\.|request\.|socket|postMessage/i
    ],
    singleThreaded: true,
    concurrencyKeywords: [/Worker|SharedArrayBuffer|Atomics/],
    memoryUnsafe: false,
    unsafeOperations: [/eval|Function\(|new Function|vm\.runInContext/],
    safetyChecks: [/typeof|instanceof|Array\.isArray/],
    userInputAPIs: [
      /req\.|request\.|body|query|params|headers|cookies/i,
      /fetch|XMLHttpRequest|postMessage/i
    ],
    deserializationAPIs: [/JSON\.parse|eval|deserialize|decode/i]
  },

  python: {
    compilerCode: [/compile|ast|bytecode/i],
    runtimeCode: [/\.py$|\/src\/|\/lib\//],
    startupCode: [/__init__|__main__|setup/],
    testCode: [/test_|_test\.py$|\/tests\/|\/test\//],
    outputFunctions: [/^(write|print|dump|serialize|encode)/i],
    inputFunctions: [/^(read|input|load|parse|decode|deserialize)/i],
    validationFunctions: [/^(validate|check|verify|assert|ensure)/i],
    embedderAPIs: [/^__|^_[a-z]/], // Private/internal
    externalAPIs: [
      /flask|django|fastapi|request|socket|input|stdin/i
    ],
    singleThreaded: false, // Has GIL but supports threading
    concurrencyKeywords: [/threading|multiprocessing|asyncio|concurrent/i],
    memoryUnsafe: false,
    unsafeOperations: [/eval|exec|compile|__import__|pickle\.loads/],
    safetyChecks: [/isinstance|hasattr|type\(/],
    userInputAPIs: [
      /request\.|input\(|stdin|argv|environ|flask|django/i
    ],
    deserializationAPIs: [/pickle\.loads|json\.loads|eval|yaml\.load/i]
  },

  go: {
    compilerCode: [/\/compiler\//],
    runtimeCode: [/\.go$|\/pkg\/|\/internal\//],
    startupCode: [/^init\(|^main\(/],
    testCode: [/_test\.go$/],
    outputFunctions: [/^(Write|Print|Marshal|Encode|Serialize)/],
    inputFunctions: [/^(Read|Scan|Unmarshal|Decode|Deserialize|Parse)/],
    validationFunctions: [/^(Validate|Check|Verify|Assert)/],
    embedderAPIs: [/^unsafe\.|^reflect\.|^runtime\./],
    externalAPIs: [
      /http\.Request|net\.|io\.Reader|os\.Stdin|flag\./i
    ],
    singleThreaded: false,
    concurrencyKeywords: [/\bgo\s+func|chan|goroutine|sync\./],
    memoryUnsafe: false, // Mostly safe but has unsafe package
    unsafeOperations: [/unsafe\.|reflect\./],
    safetyChecks: [/if err != nil|panic|recover/],
    userInputAPIs: [
      /http\.Request|net\.Conn|io\.Reader|os\.Stdin|flag\./
    ],
    deserializationAPIs: [/json\.Unmarshal|xml\.Unmarshal|gob\.Decode/]
  },

  rust: {
    compilerCode: [/rustc|macro|proc_macro/i],
    runtimeCode: [/\.rs$|\/src\//],
    startupCode: [/^fn main/],
    testCode: [/#\[test\]|_test\.rs$|\/tests\//],
    outputFunctions: [/^(write|print|serialize|encode)/i],
    inputFunctions: [/^(read|parse|deserialize|decode|from_str)/i],
    validationFunctions: [/^(validate|check|verify|assert)/i],
    embedderAPIs: [/^unsafe|^std::mem|^std::ptr/],
    externalAPIs: [
      /hyper|reqwest|tokio|std::io|std::net/i
    ],
    singleThreaded: false,
    concurrencyKeywords: [/async|await|tokio|thread|spawn|Arc|Mutex/],
    memoryUnsafe: false, // Memory safe by default
    unsafeOperations: [/\bunsafe\s*\{/],
    safetyChecks: [/Option|Result|unwrap|expect|match/],
    userInputAPIs: [
      /std::io::stdin|std::env::args|hyper::Request|reqwest/i
    ],
    deserializationAPIs: [/serde|from_str|parse|decode/i]
  },

  java: {
    compilerCode: [/javac|compiler|annotation/i],
    runtimeCode: [/\.java$|\/src\//],
    startupCode: [/^public static void main/],
    testCode: [/@Test|Test\.java$|\/test\//],
    outputFunctions: [/^(write|print|serialize|encode)/i],
    inputFunctions: [/^(read|parse|deserialize|decode|scanner)/i],
    validationFunctions: [/^(validate|check|verify|assert)/i],
    embedderAPIs: [/^sun\.|^com\.sun\.|\.internal\./],
    externalAPIs: [
      /HttpServlet|Socket|InputStream|Scanner|BufferedReader/i
    ],
    singleThreaded: false,
    concurrencyKeywords: [/\bThread|Runnable|ExecutorService|synchronized|concurrent/],
    memoryUnsafe: false,
    unsafeOperations: [/Runtime\.exec|ProcessBuilder|Reflection|deserialize/],
    safetyChecks: [/instanceof|Objects\.requireNonNull|Optional/],
    userInputAPIs: [
      /HttpServletRequest|Socket|InputStream|Scanner|System\.in/i
    ],
    deserializationAPIs: [
      /ObjectInputStream|readObject|JSON\.parse|XMLDecoder/i
    ]
  },

  csharp: {
    compilerCode: [/Roslyn|Compiler|CodeGenerator/i],
    runtimeCode: [/\.cs$|\/src\//],
    startupCode: [/^static void Main/],
    testCode: [/\[Test\]|\.Tests\.|\/test\//],
    outputFunctions: [/^(Write|Print|Serialize|Encode)/i],
    inputFunctions: [/^(Read|Parse|Deserialize|Decode)/i],
    validationFunctions: [/^(Validate|Check|Verify|Assert)/i],
    embedderAPIs: [/^System\.Runtime|^Internal\./],
    externalAPIs: [
      /HttpRequest|Socket|Stream|Console\.ReadLine/i
    ],
    singleThreaded: false,
    concurrencyKeywords: [/\bTask|async|await|Thread|Parallel|lock/],
    memoryUnsafe: false,
    unsafeOperations: [/\bunsafe\s*\{|Marshal|IntPtr/],
    safetyChecks: [/if.*null|\?\.|\?\?|ArgumentNullException/],
    userInputAPIs: [
      /HttpRequest|Socket|Stream|Console\.ReadLine|WebClient/i
    ],
    deserializationAPIs: [
      /JsonConvert|XmlSerializer|BinaryFormatter|Deserialize/i
    ]
  },

  php: {
    compilerCode: [/opcache|compiler/i],
    runtimeCode: [/\.php$|\/src\//],
    startupCode: [/^require|^include|bootstrap/i],
    testCode: [/Test\.php$|\/tests\/|PHPUnit/],
    outputFunctions: [/^(echo|print|write|serialize|encode)/i],
    inputFunctions: [/^(read|parse|unserialize|decode|file_get)/i],
    validationFunctions: [/^(validate|check|verify|assert|filter)/i],
    embedderAPIs: [/^__/],
    externalAPIs: [
      /\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$_SERVER|file_get_contents/i
    ],
    singleThreaded: true,
    concurrencyKeywords: [/pcntl_fork|swoole|reactphp/i],
    memoryUnsafe: false,
    unsafeOperations: [/eval|assert|unserialize|system|exec|shell_exec/],
    safetyChecks: [/isset|empty|filter_var|is_array/],
    userInputAPIs: [
      /\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$_FILES|\$_SERVER/
    ],
    deserializationAPIs: [/unserialize|json_decode|xml_parse/i]
  },

  ruby: {
    compilerCode: [/parser|compiler|ripper/i],
    runtimeCode: [/\.rb$|\/lib\/|\/app\//],
    startupCode: [/^require|^load|initialize/],
    testCode: [/_spec\.rb$|_test\.rb$|\/spec\/|\/test\//],
    outputFunctions: [/^(puts|print|write|serialize|encode)/i],
    inputFunctions: [/^(gets|read|parse|deserialize|decode)/i],
    validationFunctions: [/^(validate|check|verify|assert)/i],
    embedderAPIs: [/^__|^_[a-z]/],
    externalAPIs: [
      /Rack::Request|Sinatra|Rails|gets|STDIN|ARGV/i
    ],
    singleThreaded: false,
    concurrencyKeywords: [/Thread|Fiber|concurrent-ruby|parallel/i],
    memoryUnsafe: false,
    unsafeOperations: [/eval|instance_eval|class_eval|send|Marshal\.load/],
    safetyChecks: [/raise|rescue|respond_to\?|is_a\?/],
    userInputAPIs: [
      /params|request|STDIN|ARGV|gets/i
    ],
    deserializationAPIs: [/Marshal\.load|YAML\.load|JSON\.parse/i]
  },

  unknown: {
    compilerCode: [/compile|codegen|ast|parser/i],
    runtimeCode: [/execute|runtime|main/i],
    startupCode: [/init|setup|bootstrap|main/i],
    testCode: [/test|spec|unittest/i],
    outputFunctions: [/write|print|emit|output|serialize/i],
    inputFunctions: [/read|parse|input|deserialize|load/i],
    validationFunctions: [/check|validate|verify|assert/i],
    embedderAPIs: [/internal|private|^_/i],
    externalAPIs: [/http|socket|request|input|stdin/i],
    singleThreaded: false,
    concurrencyKeywords: [/thread|async|concurrent|parallel|mutex/i],
    memoryUnsafe: false,
    unsafeOperations: [/unsafe|malloc|free|exec|eval/i],
    safetyChecks: [/check|assert|validate|if.*null/i],
    userInputAPIs: [/request|input|socket|http|stdin|argv/i],
    deserializationAPIs: [/parse|deserialize|decode|unmarshal/i]
  }
};

/**
 * Detect primary language from file extensions in codebase
 */
export function detectLanguage(files: Array<{ path: string; language?: string }>): Language {
  const extensionCounts: Record<string, number> = {};

  // Normalize language names to canonical types
  const normalizeLanguage = (lang: string): Language => {
    const normalized = lang.toLowerCase().trim();

    const langMap: Record<string, Language> = {
      'c++': 'cpp',
      'cpp': 'cpp',
      'c': 'c',
      'javascript': 'javascript',
      'js': 'javascript',
      'typescript': 'typescript',
      'ts': 'typescript',
      'python': 'python',
      'py': 'python',
      'go': 'go',
      'golang': 'go',
      'rust': 'rust',
      'rs': 'rust',
      'java': 'java',
      'c#': 'csharp',
      'csharp': 'csharp',
      'cs': 'csharp',
      'php': 'php',
      'ruby': 'ruby',
      'rb': 'ruby'
    };

    return langMap[normalized] || 'unknown';
  };

  for (const file of files) {
    // Use pre-detected language if available
    if (file.language) {
      const normalized = normalizeLanguage(file.language);
      extensionCounts[normalized] = (extensionCounts[normalized] || 0) + 1;
      continue;
    }

    // Detect from extension
    const ext = file.path.split('.').pop()?.toLowerCase();
    if (!ext) continue;

    const langMap: Record<string, Language> = {
      'cpp': 'cpp', 'cc': 'cpp', 'cxx': 'cpp', 'hpp': 'cpp', 'hxx': 'cpp', 'h': 'cpp',
      'c': 'c',
      'js': 'javascript', 'mjs': 'javascript', 'cjs': 'javascript',
      'ts': 'typescript', 'tsx': 'typescript',
      'py': 'python', 'pyi': 'python',
      'go': 'go',
      'rs': 'rust',
      'java': 'java',
      'cs': 'csharp',
      'php': 'php',
      'rb': 'ruby'
    };

    const lang = langMap[ext];
    if (lang) {
      extensionCounts[lang] = (extensionCounts[lang] || 0) + 1;
    }
  }

  // Find most common language
  let maxCount = 0;
  let detectedLang: Language = 'unknown';

  for (const [lang, count] of Object.entries(extensionCounts)) {
    if (count > maxCount) {
      maxCount = count;
      detectedLang = lang as Language;
    }
  }

  return detectedLang;
}
