const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const url = "https://github.com/WireGuard/wireguard-go/releases/download/0.0.20230223/wireguard-go-windows-amd64.zip";
const dest = "wg.zip";
const targetDir = "src-tauri/target/debug";

console.log("Downloading wireguard-go using System Curl...");

try {
    // Force curl to follow redirects
    execSync(`curl -L -o ${dest} "${url}"`, { stdio: 'inherit' });

    console.log("Download complete. Extracting...");

    // Check file size
    const stats = fs.statSync(dest);
    console.log(`Downloaded size: ${stats.size} bytes`);
    if (stats.size < 1000) {
        throw new Error("Download too small - likely failed");
    }

    execSync(`powershell -Command "Expand-Archive -Force ${dest} -DestinationPath ."`, { stdio: 'inherit' });
    console.log("Extracted.");

    if (!fs.existsSync(targetDir)) {
        fs.mkdirSync(targetDir, { recursive: true });
    }

    fs.copyFileSync("wireguard-go.exe", path.join(targetDir, "wireguard-go.exe"));
    console.log(`Success! Moved wireguard-go.exe to ${targetDir}`);

    // Cleanup
    fs.unlinkSync(dest);
    if (fs.existsSync("wireguard-go.exe")) fs.unlinkSync("wireguard-go.exe");

} catch (e) {
    console.error("Operation failed: " + e.message);
}
