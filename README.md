Hashkitten - Advanced Hash Toolkit
<p align="center">
<img src="https://www.google.com/search?q=https://i.postimg.cc/NfLR2hrw/Gemini_Generated_Image_at6166at6166at61-removebg-preview.png" alt="Hashkitten Logo" width="200"/>
</p>

<p align="center">
A versatile, all-in-one crypto utility for hashing, encoding, and more. Built with modern web technologies, Hashkitten is a single-page application that runs entirely in your browser, ensuring your data stays private.
</p>

✨ Features
Hashkitten is a comprehensive toolkit designed for developers, security professionals, and anyone who needs to work with cryptographic hashes and other data transformations.

File Hashing: Calculate hashes for up to 10 local files at once using multiple algorithms. Features a drag-and-drop interface with real-time progress bars powered by Web Workers for a non-blocking UI.

Text Hashing: Instantly generate a hash from any text or string input.

Hash Comparison: Directly compare two hashes to check for equality.

HMAC Generator: Create Hash-based Message Authentication Codes using a secret key for data integrity and authenticity.

Base64 Utility: A simple and fast tool for encoding plain text to Base64 and decoding it back in real-time.

URL Encoder/Decoder: Encode and decode text for safe use in URLs.

Checksum Verification: Verify the integrity of a set of local files against a standard checksum file (e.g., sha256sums.txt).

Password Strength Analyzer: Get instant, personalized feedback on the strength of your passwords with a visual strength bar and actionable suggestions.

Supported Algorithms
SHA-256 (Recommended)

SHA-512

SHA-384

SHA-1 (Legacy)

MD5 (For non-security checksums)

UI & UX
Fully Responsive Design: A sleek, modern interface that works beautifully on any device, from mobile to desktop.

Dark Mode by Default: An immersive dark theme with an interactive, mouse-aware gradient background.

Floating Navigation: An intuitive floating tab bar that stays accessible as you scroll.

Animations & Micro-interactions: Smooth transitions and subtle animations provide a polished and satisfying user experience.

Persistent State: The app remembers your last-used tab and algorithm, so you can pick up right where you left off.

🚀 How to Use
Hashkitten is designed to be incredibly simple to run. Since it's a completely self-contained, single-file application, there are no dependencies or build steps required.

Save the Code: Save the entire file_hash_tool code as an index.html file.

Open in Browser: Open the index.html file in any modern web browser (like Chrome, Firefox, or Edge).

That's it! The application will be fully functional.

🛠️ Technologies Used
HTML5: For the structure and content of the application.

Tailwind CSS: For all styling, enabling a responsive and modern design without custom CSS files.

JavaScript (ES6+): For all application logic, interactivity, and DOM manipulation.

Web Crypto API: The browser's native, secure API for performing cryptographic operations like SHA hashing and HMAC generation.

Web Workers: Used to offload heavy file-hashing tasks to a background thread, ensuring the main UI remains fast and responsive at all times.

CryptoJS: A library used as a fallback for the MD5 hashing algorithm, which is not included in the standard Web Crypto API.
