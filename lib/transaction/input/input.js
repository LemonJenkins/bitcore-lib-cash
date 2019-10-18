'use strict';

var _ = require('lodash');
var $ = require('../../util/preconditions');
var errors = require('../../errors');
var BufferWriter = require('../../encoding/bufferwriter');
var buffer = require('buffer');
var BufferUtil = require('../../util/buffer');
var JSUtil = require('../../util/js');
var Script = require('../../script');
var Sighash = require('../sighash');
var Output = require('../output');

// var MultiSigScriptHash = require('../input/MultiSigScriptHash');
var Signature = require('../signature');


var MAXINT = 0xffffffff; // Math.pow(2, 32) - 1;
var DEFAULT_RBF_SEQNUMBER = MAXINT - 2;
var DEFAULT_SEQNUMBER = MAXINT;
var DEFAULT_LOCKTIME_SEQNUMBER = MAXINT - 1;

function Input(params) {
  if (!(this instanceof Input)) {
    return new Input(params);
  }
  if (params) {
    return this._fromObject(params);
  }
}

Input.MAXINT = MAXINT;
Input.DEFAULT_SEQNUMBER = DEFAULT_SEQNUMBER;
Input.DEFAULT_LOCKTIME_SEQNUMBER = DEFAULT_LOCKTIME_SEQNUMBER;
Input.DEFAULT_RBF_SEQNUMBER = DEFAULT_RBF_SEQNUMBER;

Object.defineProperty(Input.prototype, 'script', {
  configurable: false,
  enumerable: true,
  get: function () {
    if (this.isNull()) {
      return null;
    }
    if (!this._script) {
      this._script = new Script(this._scriptBuffer);
      this._script._isInput = true;
    }
    return this._script;
  }
});

Input.fromObject = function (obj) {
  $.checkArgument(_.isObject(obj));
  var input = new Input();
  return input._fromObject(obj);
};

Input.prototype._fromObject = function (params) {
  var prevTxId;
  if (_.isString(params.prevTxId) && JSUtil.isHexa(params.prevTxId)) {
    prevTxId = new buffer.Buffer(params.prevTxId, 'hex');
  } else {
    prevTxId = params.prevTxId;
  }
  this.output = params.output ?
    (params.output instanceof Output ? params.output : new Output(params.output)) : undefined;
  this.prevTxId = prevTxId || params.txidbuf;
  this.outputIndex = _.isUndefined(params.outputIndex) ? params.txoutnum : params.outputIndex;
  this.sequenceNumber = _.isUndefined(params.sequenceNumber) ?
    (_.isUndefined(params.seqnum) ? DEFAULT_SEQNUMBER : params.seqnum) : params.sequenceNumber;
  if (_.isUndefined(params.script) && _.isUndefined(params.scriptBuffer)) {
    throw new errors.Transaction.Input.MissingScript();
  }
  this.setScript(params.scriptBuffer || params.script);
  return this;
};

Input.prototype.toObject = Input.prototype.toJSON = function toObject() {
  var obj = {
    prevTxId: this.prevTxId.toString('hex'),
    outputIndex: this.outputIndex,
    sequenceNumber: this.sequenceNumber,
    script: this._scriptBuffer.toString('hex'),
  };
  // add human readable form if input contains valid script
  if (this.script) {
    obj.scriptString = this.script.toString();
  }
  if (this.output) {
    obj.output = this.output.toObject();
  }
  return obj;
};

Input.fromBufferReader = function (br, params) {
  var input = new Input();
  input.prevTxId = br.readReverse(32);
  input.outputIndex = br.readUInt32LE();
  input._scriptBuffer = br.readVarLengthBuffer();
  input.sequenceNumber = br.readUInt32LE();
  // TODO: return different classes according to which input it is
  // e.g: CoinbaseInput, PublicKeyHashInput, MultiSigScriptHashInput, etc.
  if (params && params['hex']) {
    var inputLen = params['hex'].length
    if (!inputLen || inputLen % 2)
      throw new Error("Bad input")

    const hl = inputLen >> 1
    var code = new Array(hl)

    for (var i = 0; i < hl; i++) {
      code[i] = params['hex'].substr(i * 2, 2)
    }
    var inputList = inputs(code)
    var sigString = inputList[params['index']].script_sig.slice(4, (parseInt(inputList[0].script_sig.slice(2, 4), 16)) * 2 + 2)
    var signatures = []
    var utxo = params['utxos'].find(function(element) {
      return element['txid'] === input.prevTxId && input.outputIndex === element['vout'];
    });
    if (utxo['publicKey']) {
      var publicKeysString = utxo['public_keys'].map(function (key){
        return key.toString();
      });

      signatures[publicKeysString.indexOf(utxo['public_key'])] = Signature({
        prevTxId: input.prevTxId,
        outputIndex: input.outputIndex,
        inputIndex: 0,
        sigtype: 65,
        publicKey: utxo['public_key'],
        signature: sigString
      })
    }
    // var signature = Signature({prevTxId: input.prevTxId, outputIndex: input.outputIndex, inputIndex: 0, sigtype:1, publicKey: '03304971388f0136718e02beab7701268993bf9dfa263c27426a20d1f1cf099682', signature: sigString})
    input = new Input.MultiSigScriptHash(input, utxo['public_keys'], 2, signatures)

    input.output = new Output(utxo);
    // input = new Input.MultiSigScriptHash(input, params.publicKeys[PublicKey.fromString('02b88f245350ccc2cc66285dac7ab731bcbf23e48fe6f4758c88fd18cfea0c3689'), PublicKey.fromString('03304971388f0136718e02beab7701268993bf9dfa263c27426a20d1f1cf099682')], 2,[signature])
  }
  return input;
};

function toLittleEndian(bytearr) {
  return bytearr.reverse()
}
function version(bytes) {
  bytes = bytes.slice(0, 3)
  bytes = toLittleEndian(bytes)
  var formatted = bytes.join('')
  return parseInt(formatted, 16)
}

function inputs(bytes) {
  var resArr = []
  var index = 5
  var scriptlen
  var templen
  // In counter
  // next 1-9 bytes encode the number of input txs
  const inCount = parseInt(bytes[4], 16)

  for (var i = 0; i < inCount; i++) {

    var prev = toLittleEndian(bytes.slice(index, index + 36)).join('')
    var siglen = parseInt(bytes[index + 36], 16)
    const script = bytes.slice(index + 37, index + 37 + siglen).join('')
    var outindex = prev.slice(0, 8)
    var addr = prev.slice(8, prev.length)

    var seq = bytes.slice(index + 37 + siglen, index + 37 + siglen + 4).join('')
    seq = parseInt(seq, 16)
    outindex = parseInt(outindex, 16)
    prev = prev.slice(8, 72)

    resArr.push({
      output_index: outindex,
      prev_output: prev,
      script_len: siglen,
      script_sig: script,
      sequence: seq
    })
    templen = parseInt(bytes[index + 36], 16)
    index += (36 + templen + 4 + 1)
    //outputStart = 154
  }
  // outputStart = index + 1
  return resArr
}

Input.prototype.toBufferWriter = function (writer) {
  if (!writer) {
    writer = new BufferWriter();
  }
  writer.writeReverse(this.prevTxId);
  writer.writeUInt32LE(this.outputIndex);
  var script = this._scriptBuffer;
  writer.writeVarintNum(script.length);
  writer.write(script);
  writer.writeUInt32LE(this.sequenceNumber);
  return writer;
};

Input.prototype.setScript = function (script) {
  this._script = null;
  if (script instanceof Script) {
    this._script = script;
    this._script._isInput = true;
    this._scriptBuffer = script.toBuffer();
  } else if (JSUtil.isHexa(script)) {
    // hex string script
    this._scriptBuffer = new buffer.Buffer(script, 'hex');
  } else if (_.isString(script)) {
    // human readable string script
    this._script = new Script(script);
    this._script._isInput = true;
    this._scriptBuffer = this._script.toBuffer();
  } else if (BufferUtil.isBuffer(script)) {
    // buffer script
    this._scriptBuffer = new buffer.Buffer(script);
  } else {
    throw new TypeError('Invalid argument type: script');
  }
  return this;
};

/**
 * Retrieve signatures for the provided PrivateKey.
 *
 * @param {Transaction} transaction - the transaction to be signed
 * @param {PrivateKey} privateKey - the private key to use when signing
 * @param {number} inputIndex - the index of this input in the provided transaction
 * @param {number} sigType - defaults to Signature.SIGHASH_ALL
 * @param {Buffer} addressHash - if provided, don't calculate the hash of the
 *     public key associated with the private key provided
 * @abstract
 */
Input.prototype.getSignatures = function () {
  throw new errors.AbstractMethodInvoked(
    'Trying to sign unsupported output type (only P2PKH and P2SH multisig inputs are supported)' +
    ' for input: ' + JSON.stringify(this)
  );
};

Input.prototype.isFullySigned = function () {
  throw new errors.AbstractMethodInvoked('Input#isFullySigned');
};

Input.prototype.isFinal = function () {
  return this.sequenceNumber !== 4294967295;
};

Input.prototype.addSignature = function () {
  throw new errors.AbstractMethodInvoked('Input#addSignature');
};

Input.prototype.clearSignatures = function () {
  throw new errors.AbstractMethodInvoked('Input#clearSignatures');
};

Input.prototype.isValidSignature = function (transaction, signature) {
  // FIXME: Refactor signature so this is not necessary
  signature.signature.nhashtype = signature.sigtype;
  return Sighash.verify(
    transaction,
    signature.signature,
    signature.publicKey,
    signature.inputIndex,
    this.output.script,
    this.output.satoshisBN
  );
};

/**
 * @returns true if this is a coinbase input (represents no input)
 */
Input.prototype.isNull = function () {
  return this.prevTxId.toString('hex') === '0000000000000000000000000000000000000000000000000000000000000000' &&
    this.outputIndex === 0xffffffff;
};

Input.prototype._estimateSize = function () {
  return this.toBufferWriter().toBuffer().length;
};

module.exports = Input;
