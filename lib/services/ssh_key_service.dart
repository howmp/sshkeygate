import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:dartssh2/dartssh2.dart';
import 'package:pointycastle/export.dart' as pc;

/// Parsed SSH private key and its derived metadata.
///
/// Keep instances short-lived: [_keyPair] contains private key material.
class ParsedSshKey {
  final SSHKeyPair _keyPair;

  ParsedSshKey._(this._keyPair);

  String get algorithm => _keyPair.name;

  Uint8List get publicKeyBlob => _keyPair.toPublicKey().encode();

  String get fingerprint => SshKeyService.fingerprint(publicKeyBlob);

  String get unencryptedPem => _keyPair.toPem();

  Uint8List sign(Uint8List data, {int flags = 0}) {
    if (_keyPair is OpenSSHRsaKeyPair || _keyPair is RsaPrivateKey) {
      return SshKeyService._signRsa(_keyPair, data, flags);
    }
    if (flags != 0) {
      throw FormatException('非 RSA 密钥不支持签名 flags: $flags');
    }
    return _keyPair.sign(data).encode();
  }
}

/// Single entry point for SSH private-key parsing and SSH signature creation.
class SshKeyService {
  static const rsaSha2_256Flag = 2;
  static const rsaSha2_512Flag = 4;

  SshKeyService._();

  static ParsedSshKey parse(String pem, {String? passphrase}) {
    final normalizedPem = pem.replaceAll('\r\n', '\n').trim();
    if (normalizedPem.isEmpty) {
      throw const FormatException('私钥文本为空');
    }

    final keyPairs = SSHKeyPair.fromPem(normalizedPem, passphrase);
    if (keyPairs.isEmpty) {
      throw const FormatException('未找到有效密钥');
    }
    if (keyPairs.length != 1) {
      throw const FormatException('暂不支持一个文件中包含多个私钥');
    }
    return ParsedSshKey._(keyPairs.single);
  }

  static bool isEncrypted(String pem) => SSHKeyPair.isEncryptedPem(pem);

  static String fingerprint(List<int> publicKeyBlob) {
    final hash = crypto.sha256.convert(publicKeyBlob);
    return 'SHA256:${base64Encode(hash.bytes).replaceAll('=', '')}';
  }

  static Uint8List _signRsa(SSHKeyPair keyPair, Uint8List data, int flags) {
    const supportedFlags = rsaSha2_256Flag | rsaSha2_512Flag;
    if ((flags & ~supportedFlags) != 0) {
      throw FormatException('不支持的 RSA 签名 flags: $flags');
    }
    final BigInt n;
    final BigInt d;
    final BigInt p;
    final BigInt q;

    if (keyPair is OpenSSHRsaKeyPair) {
      n = keyPair.n;
      d = keyPair.d;
      p = keyPair.p;
      q = keyPair.q;
    } else if (keyPair is RsaPrivateKey) {
      n = keyPair.n;
      d = keyPair.d;
      p = keyPair.p;
      q = keyPair.q;
    } else {
      throw ArgumentError.value(keyPair, 'keyPair', '不是 RSA 私钥');
    }

    final String signatureType;
    final pc.Digest digest;
    final String digestOid;
    if ((flags & rsaSha2_512Flag) != 0) {
      signatureType = 'rsa-sha2-512';
      digest = pc.SHA512Digest();
      digestOid = '0609608648016503040203';
    } else if ((flags & rsaSha2_256Flag) != 0) {
      signatureType = 'rsa-sha2-256';
      digest = pc.SHA256Digest();
      digestOid = '0609608648016503040201';
    } else {
      signatureType = 'ssh-rsa';
      digest = pc.SHA1Digest();
      digestOid = '06052b0e03021a';
    }

    final signer = pc.RSASigner(digest, digestOid)
      ..init(
        true,
        pc.PrivateKeyParameter<pc.RSAPrivateKey>(
          pc.RSAPrivateKey(n, d, p, q),
        ),
      );
    final signature = signer.generateSignature(data);

    final writer = _SshWriter();
    writer.writeString(utf8.encode(signatureType));
    writer.writeString(signature.bytes);
    return writer.takeBytes();
  }
}

class _SshWriter {
  final _bytes = BytesBuilder(copy: false);

  void writeString(List<int> value) {
    final length = ByteData(4)..setUint32(0, value.length, Endian.big);
    _bytes.add(length.buffer.asUint8List());
    _bytes.add(value);
  }

  Uint8List takeBytes() => _bytes.takeBytes();
}
