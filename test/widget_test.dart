import 'package:flutter_test/flutter_test.dart';
import 'package:sshkeygate/theme/app_colors.dart';

void main() {
  test('应用颜色常量定义正确', () {
    expect(AppColors.primary.value, 0xFF2563EB);
    expect(AppColors.green.value, 0xFF059669);
    expect(AppColors.red.value, 0xFFDC2626);
    expect(AppColors.bg.value, 0xFFE2E8F0);
  });
}
