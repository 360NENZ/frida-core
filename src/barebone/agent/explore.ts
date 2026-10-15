console.log("Agent loading");
const cm = new CModule(File.readAllBytes("./target/aarch64-unknown-none/release/meshlink-barebone-agent"));
//const cm = new CModule(File.readAllBytes("./target/aarch64-unknown-none/debug/meshlink-barebone-agent"));

const start = new NativeFunction(cm._start, "pointer", []);
const bufferPhysicalAddress = start();
console.log("Ready! Buffer is at physical address:", bufferPhysicalAddress);
$debugger.continue();

Object.assign(globalThis, { cm, start });
