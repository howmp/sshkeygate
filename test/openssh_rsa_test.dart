import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:pointycastle/export.dart';
import 'package:sshkeygate/services/ssh_key_service.dart';

/// 真实 ssh-keygen 生成的 RSA-2048 密钥
const testRsaPrivateKey = '''-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEApf+llYCZIdIVWdwb5ODwZawY0wWru1haFAIHVjtHi6rmPYT8RB0P
hkOAfA+yLxBIil7IikcFFq4AUAiq1XFqweET1qPxvZhN4NbWdsJD+SkA0AqVEmdkFb/qiL
2LxJPgOExBKyFHIMX1qPoXf13GZfwiMozME5LNhIqKkIBQ/zgoI0P/Cj8anrokWeYd4dT6
dx6KzBPWvooyTcv2hqY59Ikq0fA2j0bXSGZmcgdTIH4McsAsbz3+9B44M8MRU1zHfk/x5h
uxsznaxlFzhL8TzWwiAOCmOREVYOLDBTe0NuSIvniTldLWr4U/BMQ8+jE1sPDNZiz0Gnr1
Iode4Y5qZQAAA8gvu/PlL7vz5QAAAAdzc2gtcnNhAAABAQCl/6WVgJkh0hVZ3Bvk4PBlrB
jTBau7WFoUAgdWO0eLquY9hPxEHQ+GQ4B8D7IvEEiKXsiKRwUWrgBQCKrVcWrB4RPWo/G9
mE3g1tZ2wkP5KQDQCpUSZ2QVv+qIvYvEk+A4TEErIUcgxfWo+hd/XcZl/CIyjMwTks2Eio
qQgFD/OCgjQ/8KPxqeuiRZ5h3h1Pp3HorME9a+ijJNy/aGpjn0iSrR8DaPRtdIZmZyB1Mg
fgxywCxvPf70HjgzwxFTXMd+T/HmG7GzOdrGUXOEvxPNbCIA4KY5ERVg4sMFN7Q25Ii+eJ
OV0tavhT8ExDz6MTWw8M1mLPQaevUih17hjmplAAAAAwEAAQAAAQASs8mcXTODjbeVmviy
kgxLrDbUyaIGVsc5U1wvwTiHmh7cJghFBVArNJ48fAk7h7ZgjprCB4vheQO0gLF8oE1ioC
D70RdKoOb/Ur0xfqQpZY7/oX2Xp/ntAGUkeFSPtohv11mNSi/JF7ych+bPVQmmEmDo+JeC
igrpKLHBY4+cnXDaNqGilc2tnwDzlQAy5kSZZLYhvo/7B1gn3X2LUA+0e87wqw68MEOVfo
BQZR81Pv/26yTWM2Bi6Wj8U5He0ugmekFN7lPBsck8r/0m7IS+SxgZrplyol/mJOMelZJK
tvXnY+p4QMbzDTc5dT+0Q4am4AoCdigynsycgnqYGGiJAAAAgQC018ojmbWfelU6Ivtl5r
FKu1Jpvmu843s4O8BUDANNT7Mu8NBKrnjsAAozEVErjaVtKls9dRKug/ZsTY1dTt9AlcXX
3DkbO8mFv8es6iOz/468HjVsn1c29NWNO/ak1qSRqs8oxdOVByHsGT16UFtLH0sITvuNZe
cBW3Wq+4KWYAAAAIEA18yyYCH3onW5ePMMJUiFSB5p0OxJ2zX2/aEdL2IUhw6O11R3hZ3q
VupHXB55pe6TE9TEZntzzpB3ysYD08C3+PwHIVzguBnfnU1/4CkvDxlCKQ0oCLSrB8tCj3
VnURW4l8OpTF0eYo9DIhM0I3OPgPP/a+7YQFNcXY/BTlNjoYkAAACBAMTr+5+BrpRkt3Wz
1ubTLYvJfNyq8+Z8NlnlHOmhNO2RflQzoazi8Dcd5kGfAgB++ZqD0hcWUrgmW/v6Vb1E0N
JytAYoFBOcKMsaUNTYU/RGv68ypEAbK6PxLmcnHn76Qyhum4UIlzgbte4CwHfqoaO8SUQv
ymvTkP9ZdbhnBhb9AAAAEGJ3YWdlbnQtcnNhLXRlc3QBAg==
-----END OPENSSH PRIVATE KEY-----''';

const testRsaPublicKeyLine =
    'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCl/6WVgJkh0hVZ3Bvk4PBlrBjTBau7WFoUAgdWO0eLquY9hPxEHQ+GQ4B8D7IvEEiKXsiKRwUWrgBQCKrVcWrB4RPWo/G9mE3g1tZ2wkP5KQDQCpUSZ2QVv+qIvYvEk+A4TEErIUcgxfWo+hd/XcZl/CIyjMwTks2EioqQgFD/OCgjQ/8KPxqeuiRZ5h3h1Pp3HorME9a+ijJNy/aGpjn0iSrR8DaPRtdIZmZyB1MgfgxywCxvPf70HjgzwxFTXMd+T/HmG7GzOdrGUXOEvxPNbCIA4KY5ERVg4sMFN7Q25Ii+eJOV0tavhT8ExDz6MTWw8M1mLPQaevUih17hjmpl sshkeygate-rsa-test';

const testRsaFingerprint = 'SHA256:GGozTvgXMnLRmWmbuUR70L6luPBV11kbgnihIMKMfUE';

void main() {
  group('SshKeyService RSA', () {
    late ParsedSshKey parsed;

    setUpAll(() {
      parsed = SshKeyService.parse(testRsaPrivateKey);
    });

    test('算法为 ssh-rsa', () {
      expect(parsed.algorithm, 'ssh-rsa');
    });

    test('公钥 blob 非空', () {
      expect(parsed.publicKeyBlob, isNotEmpty);
      expect(parsed.publicKeyBlob.length,
          greaterThan(250)); // RSA-2048 blob ≈ 270+ 字节
    });

    test('指纹与 ssh-keygen 一致', () {
      expect(parsed.fingerprint, testRsaFingerprint);
    });

    test('公钥 blob 可还原为 ssh-keygen 公钥行', () {
      final blobB64 = base64Encode(parsed.publicKeyBlob);
      final line = 'ssh-rsa $blobB64 sshkeygate-rsa-test';
      expect(line, testRsaPublicKeyLine);
    });
  });

  group('SshKeyService RSA 签名', () {
    late ParsedSshKey parsed;

    setUpAll(() {
      parsed = SshKeyService.parse(testRsaPrivateKey);
    });

    for (final testCase in [
      (flags: 0, type: 'ssh-rsa', digest: SHA1Digest(), oid: '06052b0e03021a'),
      (
        flags: SshKeyService.rsaSha2_256Flag,
        type: 'rsa-sha2-256',
        digest: SHA256Digest(),
        oid: '0609608648016503040201'
      ),
      (
        flags: SshKeyService.rsaSha2_512Flag,
        type: 'rsa-sha2-512',
        digest: SHA512Digest(),
        oid: '0609608648016503040203'
      ),
    ]) {
      test('${testCase.type} flags 生成可验证签名', () {
        final data = Uint8List.fromList('test rsa sign'.codeUnits);
        final signature = _SshReader(parsed.sign(data, flags: testCase.flags));
        expect(utf8.decode(signature.readString()), testCase.type);

        final publicKey = _SshReader(parsed.publicKeyBlob);
        expect(utf8.decode(publicKey.readString()), 'ssh-rsa');
        final e = _bytesToBigInt(publicKey.readString());
        final n = _bytesToBigInt(publicKey.readString());

        final verifier = RSASigner(testCase.digest, testCase.oid)
          ..init(false, PublicKeyParameter<RSAPublicKey>(RSAPublicKey(n, e)));
        expect(
          verifier.verifySignature(
            data,
            RSASignature(signature.readString()),
          ),
          isTrue,
        );
      });
    }
  });
}

class _SshReader {
  final Uint8List _bytes;
  int _offset = 0;

  _SshReader(this._bytes);

  Uint8List readString() {
    final length = ByteData.sublistView(_bytes, _offset, _offset + 4)
        .getUint32(0, Endian.big);
    _offset += 4;
    final value = _bytes.sublist(_offset, _offset + length);
    _offset += length;
    return value;
  }
}

BigInt _bytesToBigInt(List<int> bytes) {
  var result = BigInt.zero;
  for (final byte in bytes) {
    result = (result << 8) | BigInt.from(byte);
  }
  return result;
}
