// tests go here; this will not be compiled when this package is used as an extension.

game.consoleOverlay.setVisible(true, 1);

function makeRandomBuffer(count: number) {
    const buf = pins.createBuffer(count);
    for (let i = 0; i < buf.length; i++) buf[i] = randint(0, 255);
    return buf
}

const shasha = new Chacha20(makeRandomBuffer(32), makeRandomBuffer(12))
const utf8decode = new UTF8Decoder()
const msg = "Hello, World!\0"
console.log(`original msg: ${msg}`)
let ubuf = shasha.encrypt(control.createBufferFromUTF8(msg), 5);
utf8decode.add(ubuf)
let utxt = utf8decode.decode()
console.log(`encrypted msg: ${utxt}`);
console.log(`encrypted key: "${shasha.enckey.map(v => v.toHex()).join(",").substr(0, 80)}..."`);
let tmp = shasha.decrypt(ubuf, 5);
ubuf = tmp;
utf8decode.add(ubuf)
utxt = utf8decode.decode()
console.log(`decrypted msg: ${utxt}`)