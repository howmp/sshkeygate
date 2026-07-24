import 'package:flutter/material.dart';

/// 应用颜色常量，与 HTML 原型保持一致
class AppColors {
  AppColors._();

  // 主色调
  static const Color primary = Color(0xFF2563EB);
  static const Color primaryHover = Color(0xFF1D4ED8);
  static const Color primaryLight = Color(0xFFEFF6FF);

  // 绿色（成功/信任）
  static const Color green = Color(0xFF059669);
  static const Color greenHover = Color(0xFF047857);
  static const Color greenBg = Color(0xFFDCFCE7);
  static const Color greenText = Color(0xFF15803D);

  // 红色（危险/锁定）
  static const Color red = Color(0xFFDC2626);
  static const Color redHover = Color(0xFFEF4444);
  static const Color redBg = Color(0xFFFEF2F2);
  static const Color redText = Color(0xFFDC2626);

  // 黄色（警告弹窗）
  static const Color warningBg = Color(0xFFFEF3C7);
  static const Color warningStroke = Color(0xFFD97706);

  // 背景
  static const Color bg = Color(0xFFE2E8F0);
  static const Color surface = Color(0xFFF1F5F9);
  static const Color white = Color(0xFFFFFFFF);

  // 边框
  static const Color border = Color(0xFFE2E8F0);
  static const Color borderLight = Color(0xFFF1F5F9);

  // 文字
  static const Color textPrimary = Color(0xFF0F172A);
  static const Color textBody = Color(0xFF1E293B);
  static const Color textSecondary = Color(0xFF475569);
  static const Color textMuted = Color(0xFF64748B);
  static const Color textLight = Color(0xFF94A3B8);

  // 标签
  static const Color tagBg = Color(0xFFF1F5F9);
  static const Color inputBg = Color(0xFFF8FAFC);
  static const Color disabledBg = Color(0xFFCBD5E1);

  // 聚焦
  static const Color focusBorder = Color(0xFF93C5FD);
  static const Color focusShadow = Color(0xFFDBEAFE);
}
