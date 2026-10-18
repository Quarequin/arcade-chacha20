
class Chacha20 {
    _rounds: uint16 = 20;
    _sigma: Buffer = hex`
65787961
6e642033
322d6279
7465206b
    `; //constants (little endian)
    // [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    _param: Buffer = pins.createBuffer(64);
    _keystream: Buffer
    _keystack: Buffer[];

    constructor(
        public readonly key: Buffer,
        public readonly nonce: Buffer,
        public readonly counter?: number,
    ) {
        if (!key || key.length !== 32)
            throw "Key should be 32 byte array!";
        
        if (!nonce || nonce.length !== 12)
            throw "Nonce should be 12 byte array!";
        
        if (!counter)
            this.counter = 0;

        this._param.write(0, this._sigma);
        this._param.write(16, this.key);
        this._param.setNumber(NumberFormat.UInt32LE, 48, this.counter);
        this._param.write(52, this.nonce);

        this._keystream = pins.createBuffer(64);
        
    }

    _byteCounter: uint32 = 0;

    _chacha() {
        let mix = pins.createBuffer(64);
        let i = 0;
        let b = 0;

        mix.write(0, this._param);

        for (i = 0; i < this._rounds; i += 2)
            this._quarterround(mix, 0, 4, 8, 12),
            this._quarterround(mix, 1, 5, 9, 13),
            this._quarterround(mix, 2, 6, 10, 14),
            this._quarterround(mix, 3, 7, 11, 15),

            this._quarterround(mix, 0, 5, 10, 15),
            this._quarterround(mix, 1, 6, 11, 12),
            this._quarterround(mix, 2, 7, 8, 13),
            this._quarterround(mix, 3, 4, 9, 14);
        
        for (i = 0; i < 16; i++)
            mix.setNumber(NumberFormat.UInt32LE, i << 2,
                mix.getNumber(NumberFormat.UInt32LE, i << 2) +
                this._param.getNumber(NumberFormat.UInt32LE, i << 2)
            );
        this._keystream.write(0, mix);
    }

    private _quarterround(output: Buffer, a: number, b: number, c: number, d: number) {
        let t = pins.createBuffer(4);
        output.setNumber(NumberFormat.UInt32LE, a << 2,
            output.getNumber(NumberFormat.UInt32LE, a << 2) +
            output.getNumber(NumberFormat.UInt32LE, b << 2)
        );
        t.setNumber(NumberFormat.UInt32LE, 0,
            output.getNumber(NumberFormat.UInt32LE, d << 2) ^
            output.getNumber(NumberFormat.UInt32LE, a << 2)
        );
        t.rotate(16);
        output.setNumber(NumberFormat.UInt32LE, d << 2,
            t.getNumber(NumberFormat.UInt32LE, 0)
        );
        //output[d] = this._rotl(output[d] ^ (output[a] += output[b]), 16)
        output.setNumber(NumberFormat.UInt32LE, c << 2,
            output.getNumber(NumberFormat.UInt32LE, c << 2) +
            output.getNumber(NumberFormat.UInt32LE, d << 2)
        );
        t.setNumber(NumberFormat.UInt32LE, 0,
            output.getNumber(NumberFormat.UInt32LE, b << 2) ^
            output.getNumber(NumberFormat.UInt32LE, c << 2)
        );
        t.rotate(12);
        output.setNumber(NumberFormat.UInt32LE, b << 2,
            t.getNumber(NumberFormat.UInt32LE, 0)
        );
        //output[b] = this._rotl(output[b] ^ (output[c] += output[d]), 12)
        output.setNumber(NumberFormat.UInt32LE, a << 2,
            output.getNumber(NumberFormat.UInt32LE, a << 2) +
            output.getNumber(NumberFormat.UInt32LE, b << 2)
        );
        t.setNumber(NumberFormat.UInt32LE, 0,
            output.getNumber(NumberFormat.UInt32LE, d << 2) ^
            output.getNumber(NumberFormat.UInt32LE, a << 2)
        );
        t.rotate(8);
        output.setNumber(NumberFormat.UInt32LE, d << 2,
            t.getNumber(NumberFormat.UInt32LE, 0)
        );
        //output[d] = this._rotl(output[d] ^ (output[a] += output[b]), 8)
        output.setNumber(NumberFormat.UInt32LE, c << 2,
            output.getNumber(NumberFormat.UInt32LE, c << 2) +
            output.getNumber(NumberFormat.UInt32LE, d << 2)
        );
        t.setNumber(NumberFormat.UInt32LE, 0,
            output.getNumber(NumberFormat.UInt32LE, b << 2) ^
            output.getNumber(NumberFormat.UInt32LE, d << 2)
        );
        t.rotate(7);
        output.setNumber(NumberFormat.UInt32LE, b << 2,
            t.getNumber(NumberFormat.UInt32LE, 0)
        );
        //output[b] = this._rotl(output[b] ^ (output[c] += output[d]), 7)

        // JavaScript hack to make UINT32 :) //
        //output[a] >>>= 0
        //output[b] >>>= 0
        //output[c] >>>= 0
        //output[d] >>>= 0
    }

    private _get32(data: Buffer, idx: number): number {
        return data.getNumber(NumberFormat.UInt32LE, idx << 2);
        //return data[idx++] ^ (data[idx++] << 8) ^ (data[idx++] << 16) ^ (data[idx] << 24);
    }

    private _rotl(data: number, shift: number): number {
        //if (data.length !== 4) return null;
        //data.rotate(shift);
        //return data;
        return ((data << shift) | (data >>> (32 - shift)));
    }

    encrypt(data: Buffer, count?: number): Buffer {
        if (!count) count = 1;
        data = this._update(data, true, false);
        if (count > 1) for (let _ = 0; _ < count - 1; _++) data = this._update(data, false, false);
        return data
    }

    decrypt(data: Buffer, count?: number): Buffer {
        if (!count) count = 1;
        data = this._update(data, true, true);
        if (count > 1) for (let _ = 0; _ < count - 1; _++) data = this._update(data, false, true);
        return data
    }

    private _update(data: Buffer, reset: boolean, reverse: boolean) {
        if (!(data) || data.length === 0) {
            throw ('Data should be type of bytes (Uint8Array) and not empty!')
        }

        if (reset) this._byteCounter = 0
        if (!reverse && reset) this._keystack = [];

        const output = pins.createBuffer(data.length);

        // core function, build block and xor with input data //
        for (let i = 0; i < data.length; i++) {
            if (this._byteCounter === 0 || this._byteCounter === 64) {
                // generate new block //
                if (reverse && this._keystack.length < 1) throw ('this keystack data be not empty!');
                if (reverse && this._keystack.length > 0) this._keystream = this._keystack.shift();
                if (!reverse) this._chacha(), this._keystack.push(this._keystream.slice());
                // counter increment //
                this._param.setNumber(NumberFormat.UInt32LE, 48,
                    this._param.getNumber(NumberFormat.UInt32LE, 48) + 1
                );

                // reset internal counter //
                this._byteCounter = 0
            }

            output[i] = data[i] ^ this._keystream[this._byteCounter++]
        }

        return output
    }
}