// Community Threat Reporting and Reputation Screen for CyberShield

import 'package:flutter/material.dart';
import 'package:cybershield/core/theme/app_theme.dart';
import 'package:cybershield/core/widgets/cyber_card.dart';
import 'package:cybershield/core/widgets/cyber_badge.dart';
import 'package:cybershield/core/widgets/cyber_loading_state.dart';
import 'package:cybershield/core/widgets/cyber_error_state.dart';
import 'package:cybershield/core/widgets/cyber_empty_state.dart';
import 'package:cybershield/core/widgets/nav_drawer.dart';
import 'package:cybershield/core/navigation/app_router.dart';
import 'package:cybershield/core/services/api_service.dart';
import 'package:cybershield/core/services/firestore_history_service.dart';
import 'package:cybershield/core/models/community_report.dart';

class _ThreatPreset {
  final String label;
  final String category;
  final String target;
  final String title;
  final String description;
  final List<String> tags;
  final Color color;

  const _ThreatPreset({
    required this.label,
    required this.category,
    required this.target,
    required this.title,
    required this.description,
    required this.tags,
    required this.color,
  });
}

class CommunityReportsScreen extends StatefulWidget {
  const CommunityReportsScreen({super.key});

  @override
  State<CommunityReportsScreen> createState() => _CommunityReportsScreenState();
}

class _CommunityReportsScreenState extends State<CommunityReportsScreen>
    with SingleTickerProviderStateMixin {
  late TabController _tabController;

  // Feed state
  bool _isLoadingReports = true;
  String? _reportsError;
  List<CommunityReport> _reports = [];
  CommunityStats? _stats;
  String _selectedCategoryFilter = 'ALL';
  final TextEditingController _searchController = TextEditingController();

  // Reputation lookup state
  String _lookupCategory = 'phone';
  final TextEditingController _lookupTargetController = TextEditingController();
  bool _isLookingUp = false;
  CommunityReputation? _lookupResult;
  String? _lookupError;

  // Submission form state
  final _formKey = GlobalKey<FormState>();
  String _formCategory = 'phone';
  final TextEditingController _formTargetController = TextEditingController();
  final TextEditingController _formTitleController = TextEditingController();
  final TextEditingController _formDescriptionController = TextEditingController();
  final List<String> _selectedTags = [];
  bool _isSubmitting = false;
  String? _submitError;
  String? _submitSuccessId;

  static const List<String> _availableCategories = [
    'phone',
    'sms',
    'url',
    'qr',
    'email',
    'app',
  ];

  static const List<String> _commonTags = [
    'phishing',
    'impersonation',
    'financial_fraud',
    'fake_otp',
    'robocall',
    'malware_payload',
    'lottery_scam',
    'tech_support_scam',
    'extortion',
  ];

  static const List<_ThreatPreset> _presets = [
    _ThreatPreset(
      label: 'IRS Phone Robocall',
      category: 'phone',
      target: '+1 (800) 555-0199',
      title: 'Automated IRS tax warrant robocall',
      description: 'Robocall claimed immediate arrest unless overdue taxes paid via gift card.',
      tags: ['robocall', 'impersonation', 'financial_fraud'],
      color: Color(0xFFBF5AF2),
    ),
    _ThreatPreset(
      label: 'USPS Delivery Scam SMS',
      category: 'sms',
      target: 'USPS: Package cannot be delivered due to incomplete address. Update at http://usps-redelivery-post.top/track',
      title: 'Fake USPS package fee smishing',
      description: 'Demands \$1.95 redelivery fee to capture credit card credentials.',
      tags: ['phishing', 'fake_otp', 'impersonation'],
      color: Color(0xFF5E5CE6),
    ),
    _ThreatPreset(
      label: 'Fake PayPal Login URL',
      category: 'url',
      target: 'https://paypal-security-verification.xyz/login',
      title: 'Credential harvesting PayPal phishing page',
      description: 'Exact replica of PayPal login with OTP capture field.',
      tags: ['phishing', 'financial_fraud'],
      color: Color(0xFF0A84FF),
    ),
    _ThreatPreset(
      label: 'Fake Banking APK',
      category: 'app',
      target: 'com.secure.sbi.netbanking.update',
      title: 'Malicious banking trojan APK',
      description: 'Injected remote access trojan stealing 2FA SMS tokens.',
      tags: ['malware_payload', 'financial_fraud'],
      color: Color(0xFFFF9F0A),
    ),
  ];

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 2, vsync: this);
    _loadInitialData();
  }

  @override
  void dispose() {
    _tabController.dispose();
    _searchController.dispose();
    _lookupTargetController.dispose();
    _formTargetController.dispose();
    _formTitleController.dispose();
    _formDescriptionController.dispose();
    super.dispose();
  }

  Future<void> _loadInitialData() async {
    await Future.wait([
      _fetchReports(),
      _fetchStats(),
    ]);
  }

  Future<void> _fetchStats() async {
    try {
      final stats = await ApiService.getCommunityStats();
      if (mounted && stats != null) {
        setState(() {
          _stats = stats;
        });
      }
    } catch (_) {}
  }

  Future<void> _fetchReports() async {
    setState(() {
      _isLoadingReports = true;
      _reportsError = null;
    });

    try {
      final list = await ApiService.getCommunityReports(
        category: _selectedCategoryFilter,
        search: _searchController.text.trim().isEmpty ? null : _searchController.text.trim(),
      );

      if (mounted) {
        setState(() {
          _isLoadingReports = false;
          _reports = list;
        });
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _isLoadingReports = false;
          _reportsError = 'Failed to load community reports: $e';
        });
      }
    }
  }

  Future<void> _performReputationLookup() async {
    final target = _lookupTargetController.text.trim();
    if (target.isEmpty) return;

    setState(() {
      _isLookingUp = true;
      _lookupResult = null;
      _lookupError = null;
    });

    try {
      final rep = await ApiService.getCommunityReputation(
        category: _lookupCategory,
        target: target,
      );

      if (mounted) {
        setState(() {
          _isLookingUp = false;
          _lookupResult = rep;
          if (rep == null) {
            _lookupError = 'Target not found in reputation database.';
          }
        });
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _isLookingUp = false;
          _lookupError = 'Reputation lookup failed: $e';
        });
      }
    }
  }

  Future<void> _submitReport() async {
    if (!_formKey.currentState!.validate()) return;

    setState(() {
      _isSubmitting = true;
      _submitError = null;
      _submitSuccessId = null;
    });

    try {
      final res = await ApiService.submitCommunityReport(
        category: _formCategory,
        target: _formTargetController.text.trim(),
        title: _formTitleController.text.trim(),
        description: _formDescriptionController.text.trim(),
        tags: _selectedTags,
      );

      if (!mounted) return;

      if (res['success'] == true) {
        final report = res['report'] as CommunityReport;
        setState(() {
          _isSubmitting = false;
          _submitSuccessId = report.id;
        });

        // Also record to user's Cloud Firestore
        if (FirestoreHistoryService.instance.isAuthenticated) {
          await FirestoreHistoryService.instance.recordCommunityReport(
            reportId: report.id,
            category: report.category,
            target: report.target,
            title: report.title,
            description: report.description,
            tags: report.tags,
          );
        }

        if (!mounted) return;

        // Show success snackbar
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Report ${report.id} submitted! Thank you for protecting the community.'),
            backgroundColor: AppColors.safe,
          ),
        );

        // Reset form fields
        _formTargetController.clear();
        _formTitleController.clear();
        _formDescriptionController.clear();
        setState(() {
          _selectedTags.clear();
        });

        // Refresh feed & stats
        _fetchReports();
        _fetchStats();
      } else {
        setState(() {
          _isSubmitting = false;
          _submitError = res['error']?.toString() ?? 'Failed to submit report.';
        });
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _isSubmitting = false;
          _submitError = 'Submission failed: $e';
        });
      }
    }
  }

  void _applyPreset(_ThreatPreset preset) {
    setState(() {
      _formCategory = preset.category;
      _formTargetController.text = preset.target;
      _formTitleController.text = preset.title;
      _formDescriptionController.text = preset.description;
      _selectedTags.clear();
      _selectedTags.addAll(preset.tags);
      _submitError = null;
      _submitSuccessId = null;
    });
  }

  IconData _getCategoryIcon(String category) {
    switch (category.toLowerCase()) {
      case 'phone':
        return Icons.phone_missed_rounded;
      case 'sms':
        return Icons.sms_failed_rounded;
      case 'url':
        return Icons.link_off_rounded;
      case 'qr':
        return Icons.qr_code_2_rounded;
      case 'email':
        return Icons.mark_email_unread_rounded;
      case 'app':
        return Icons.android_rounded;
      default:
        return Icons.security_rounded;
    }
  }

  Color _getCategoryColor(String category) {
    switch (category.toLowerCase()) {
      case 'phone':
        return const Color(0xFFBF5AF2);
      case 'sms':
        return const Color(0xFF5E5CE6);
      case 'url':
        return const Color(0xFF0A84FF);
      case 'qr':
        return const Color(0xFF30D158);
      case 'email':
        return const Color(0xFFBF5AF2);
      case 'app':
        return const Color(0xFFFF9F0A);
      default:
        return AppColors.primary;
    }
  }

  BadgeType _getStatusBadgeType(String status) {
    switch (status.toUpperCase()) {
      case 'VERIFIED_THREAT':
        return BadgeType.danger;
      case 'UNDER_REVIEW':
        return BadgeType.warning;
      case 'REJECTED':
        return BadgeType.info;
      case 'PENDING':
      default:
        return BadgeType.warning;
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Community Threat Intel'),
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_rounded),
          onPressed: () =>
              Navigator.pushReplacementNamed(context, AppRouter.dashboard),
        ),
        bottom: TabBar(
          controller: _tabController,
          indicatorColor: AppColors.primary,
          labelColor: AppColors.primary,
          unselectedLabelColor: AppColors.textSecondary,
          tabs: const [
            Tab(
              icon: Icon(Icons.public_rounded, size: 20),
              text: 'Threat Feed & Lookup',
            ),
            Tab(
              icon: Icon(Icons.add_moderator_rounded, size: 20),
              text: 'Report Threat',
            ),
          ],
        ),
      ),
      drawer: const NavDrawer(currentRoute: AppRouter.communityReports),
      body: TabBarView(
        controller: _tabController,
        children: [
          _buildFeedTab(),
          _buildSubmitTab(),
        ],
      ),
    );
  }

  // ---------------------------------------------------------------------------
  // Tab 1: Threat Feed & Reputation Lookup
  // ---------------------------------------------------------------------------

  Widget _buildFeedTab() {
    return RefreshIndicator(
      onRefresh: _loadInitialData,
      color: AppColors.primary,
      backgroundColor: AppColors.surface,
      child: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          // Macro Metrics Banner
          _buildStatsCard(),
          const SizedBox(height: 16),

          // Reputation Quick Lookup
          _buildLookupCard(),
          const SizedBox(height: 16),

          // Filter bar
          _buildCategoryFilterBar(),
          const SizedBox(height: 12),

          // Search field
          TextField(
            controller: _searchController,
            style: const TextStyle(color: AppColors.textPrimary, fontSize: 13),
            decoration: InputDecoration(
              hintText: 'Search by target, title, or keywords...',
              hintStyle: const TextStyle(color: AppColors.textMuted, fontSize: 13),
              prefixIcon: const Icon(Icons.search_rounded, color: AppColors.textMuted, size: 20),
              suffixIcon: _searchController.text.isNotEmpty
                  ? IconButton(
                      icon: const Icon(Icons.clear_rounded, size: 18),
                      onPressed: () {
                        _searchController.clear();
                        _fetchReports();
                      },
                    )
                  : null,
              filled: true,
              fillColor: AppColors.surfaceLight,
              contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
              border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(10),
                borderSide: const BorderSide(color: AppColors.cardBorder),
              ),
              enabledBorder: OutlineInputBorder(
                borderRadius: BorderRadius.circular(10),
                borderSide: const BorderSide(color: AppColors.cardBorder),
              ),
            ),
            onSubmitted: (_) => _fetchReports(),
          ),
          const SizedBox(height: 16),

          // Reports List or Loading/Error/Empty
          _buildReportsList(),
        ],
      ),
    );
  }

  Widget _buildStatsCard() {
    final stats = _stats;
    return CyberShieldCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              const Expanded(
                child: Row(
                  children: [
                    Icon(Icons.hub_rounded, color: AppColors.primary, size: 20),
                    SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        'Crowd Threat Intelligence',
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: TextStyle(
                          color: AppColors.textPrimary,
                          fontSize: 15,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(width: 8),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                decoration: BoxDecoration(
                  color: AppColors.primary.withValues(alpha: 0.15),
                  borderRadius: BorderRadius.circular(6),
                ),
                child: const Text(
                  'Decentralized',
                  style: TextStyle(
                    color: AppColors.primary,
                    fontSize: 10,
                    fontWeight: FontWeight.w700,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 14),
          Row(
            children: [
              _buildStatMetric(
                label: 'Total Reports',
                value: stats != null ? '${stats.totalReports}' : '...',
                color: AppColors.primary,
              ),
              _buildStatMetric(
                label: 'Unique Targets',
                value: stats != null ? '${stats.distinctTargets}' : '...',
                color: const Color(0xFF64D2FF),
              ),
              _buildStatMetric(
                label: 'Active Citizens',
                value: stats != null ? '${stats.activeReporters}' : '...',
                color: const Color(0xFF30D158),
              ),
              _buildStatMetric(
                label: 'Confirmed',
                value: stats != null ? '${stats.verifiedThreats}' : '...',
                color: AppColors.danger,
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildStatMetric({
    required String label,
    required String value,
    required Color color,
  }) {
    return Expanded(
      child: Column(
        children: [
          Text(
            value,
            style: TextStyle(
              color: color,
              fontSize: 18,
              fontWeight: FontWeight.w800,
            ),
          ),
          const SizedBox(height: 2),
          Text(
            label,
            style: const TextStyle(
              color: AppColors.textMuted,
              fontSize: 11,
              fontWeight: FontWeight.w500,
            ),
            textAlign: TextAlign.center,
          ),
        ],
      ),
    );
  }

  Widget _buildLookupCard() {
    return CyberShieldCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Row(
            children: [
              Icon(Icons.manage_search_rounded, color: AppColors.accent, size: 18),
              SizedBox(width: 8),
              Text(
                'Reputation Lookup',
                style: TextStyle(
                  color: AppColors.textPrimary,
                  fontSize: 14,
                  fontWeight: FontWeight.w700,
                ),
              ),
            ],
          ),
          const SizedBox(height: 6),
          const Text(
            'Check crowd consensus and reputation score for any digital identifier.',
            style: TextStyle(color: AppColors.textSecondary, fontSize: 12),
          ),
          const SizedBox(height: 12),
          Row(
            children: [
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 10),
                decoration: BoxDecoration(
                  color: AppColors.surfaceLight,
                  borderRadius: BorderRadius.circular(10),
                  border: Border.all(color: AppColors.cardBorder),
                ),
                child: DropdownButtonHideUnderline(
                  child: DropdownButton<String>(
                    value: _lookupCategory,
                    dropdownColor: AppColors.surface,
                    style: const TextStyle(color: AppColors.textPrimary, fontSize: 13),
                    items: _availableCategories.map((c) {
                      return DropdownMenuItem(
                        value: c,
                        child: Text(c.toUpperCase()),
                      );
                    }).toList(),
                    onChanged: (val) {
                      if (val != null) {
                        setState(() {
                          _lookupCategory = val;
                        });
                      }
                    },
                  ),
                ),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: TextField(
                  controller: _lookupTargetController,
                  style: const TextStyle(color: AppColors.textPrimary, fontSize: 13),
                  decoration: InputDecoration(
                    hintText: _lookupCategory == 'phone'
                        ? '+1 (800) 555-0199'
                        : (_lookupCategory == 'url' ? 'https://example.com' : 'Enter target...'),
                    hintStyle: const TextStyle(color: AppColors.textMuted, fontSize: 13),
                    filled: true,
                    fillColor: AppColors.surfaceLight,
                    contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
                    border: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(10),
                      borderSide: const BorderSide(color: AppColors.cardBorder),
                    ),
                    enabledBorder: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(10),
                      borderSide: const BorderSide(color: AppColors.cardBorder),
                    ),
                  ),
                  onSubmitted: (_) => _performReputationLookup(),
                ),
              ),
              const SizedBox(width: 8),
              ElevatedButton(
                onPressed: _isLookingUp ? null : _performReputationLookup,
                style: ElevatedButton.styleFrom(
                  backgroundColor: AppColors.primary,
                  foregroundColor: Colors.white,
                  padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 14),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(10),
                  ),
                ),
                child: _isLookingUp
                    ? const SizedBox(
                        width: 18,
                        height: 18,
                        child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white),
                      )
                    : const Icon(Icons.arrow_forward_rounded, size: 18),
              ),
            ],
          ),
          if (_lookupError != null) ...[
            const SizedBox(height: 10),
            Text(
              _lookupError!,
              style: const TextStyle(color: AppColors.danger, fontSize: 12),
            ),
          ],
          if (_lookupResult != null) ...[
            const SizedBox(height: 14),
            _buildReputationResultBanner(_lookupResult!),
          ],
        ],
      ),
    );
  }

  Widget _buildReputationResultBanner(CommunityReputation rep) {
    final isDanger = rep.isVerifiedThreat || rep.suspicionScore >= 60;
    final isWarning = !isDanger && rep.suspicionScore >= 30;
    final statusColor = isDanger
        ? AppColors.danger
        : (isWarning ? AppColors.warning : AppColors.safe);

    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: statusColor.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: statusColor.withValues(alpha: 0.4)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Row(
                children: [
                  Icon(
                    rep.isVerifiedThreat
                        ? Icons.gavel_rounded
                        : (rep.suspicionScore >= 30
                            ? Icons.warning_amber_rounded
                            : Icons.verified_user_rounded),
                    color: statusColor,
                    size: 18,
                  ),
                  const SizedBox(width: 8),
                  Text(
                    rep.classification,
                    style: TextStyle(
                      color: statusColor,
                      fontSize: 13,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                ],
              ),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                decoration: BoxDecoration(
                  color: statusColor.withValues(alpha: 0.2),
                  borderRadius: BorderRadius.circular(6),
                ),
                child: Text(
                  'Suspicion: ${rep.suspicionScore}/100',
                  style: TextStyle(
                    color: statusColor,
                    fontSize: 12,
                    fontWeight: FontWeight.w800,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          Text(
            'Target: ${rep.target}',
            style: const TextStyle(
              color: AppColors.textPrimary,
              fontSize: 12,
              fontWeight: FontWeight.w600,
            ),
          ),
          const SizedBox(height: 6),
          Row(
            children: [
              Text(
                'Reports: ${rep.totalReports} (${rep.distinctReporters} distinct contributors)',
                style: const TextStyle(color: AppColors.textSecondary, fontSize: 11),
              ),
              const SizedBox(width: 12),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                decoration: BoxDecoration(
                  color: AppColors.surfaceLight,
                  borderRadius: BorderRadius.circular(4),
                ),
                child: Text(
                  'Confidence: ${rep.confidence}',
                  style: const TextStyle(color: AppColors.textMuted, fontSize: 10),
                ),
              ),
            ],
          ),
          if (rep.evidenceTags.isNotEmpty) ...[
            const SizedBox(height: 8),
            Wrap(
              spacing: 6,
              runSpacing: 4,
              children: rep.evidenceTags.map((t) {
                return Container(
                  padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                  decoration: BoxDecoration(
                    color: AppColors.surfaceLight,
                    borderRadius: BorderRadius.circular(4),
                    border: Border.all(color: AppColors.cardBorder),
                  ),
                  child: Text(
                    '#${t.tag} (${t.count})',
                    style: const TextStyle(color: AppColors.textSecondary, fontSize: 10),
                  ),
                );
              }).toList(),
            ),
          ],
          const SizedBox(height: 8),
          Text(
            rep.disclaimer,
            style: const TextStyle(
              color: AppColors.textMuted,
              fontSize: 10,
              fontStyle: FontStyle.italic,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildCategoryFilterBar() {
    final filters = ['ALL', ..._availableCategories.map((c) => c.toUpperCase())];
    return SingleChildScrollView(
      scrollDirection: Axis.horizontal,
      child: Row(
        children: filters.map((cat) {
          final isSelected = _selectedCategoryFilter == cat;
          return Padding(
            padding: const EdgeInsets.only(right: 6.0),
            child: FilterChip(
              label: Text(
                cat,
                style: TextStyle(
                  fontSize: 11,
                  fontWeight: isSelected ? FontWeight.w700 : FontWeight.w500,
                  color: isSelected ? Colors.white : AppColors.textSecondary,
                ),
              ),
              selected: isSelected,
              selectedColor: AppColors.primary,
              backgroundColor: AppColors.surfaceLight,
              side: BorderSide(
                color: isSelected ? AppColors.primary : AppColors.cardBorder,
              ),
              padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
              onSelected: (selected) {
                if (selected) {
                  setState(() {
                    _selectedCategoryFilter = cat;
                  });
                  _fetchReports();
                }
              },
            ),
          );
        }).toList(),
      ),
    );
  }

  Widget _buildReportsList() {
    if (_isLoadingReports) {
      return const Center(
        child: Padding(
          padding: EdgeInsets.all(32.0),
          child: CyberLoadingState(
            title: 'Synchronizing Crowd Reports...',
            subtitle: 'Retrieving community-sourced threat intelligence',
          ),
        ),
      );
    }

    if (_reportsError != null) {
      return CyberErrorState(
        title: 'Feed Synchronization Failed',
        message: _reportsError!,
        onRetry: _fetchReports,
      );
    }

    if (_reports.isEmpty) {
      return CyberEmptyState(
        icon: Icons.shield_moon_rounded,
        title: 'No Reports Found',
        description: _selectedCategoryFilter != 'ALL'
            ? 'No community reports match the "$_selectedCategoryFilter" filter.'
            : 'No community reports have been recorded yet. Be the first to report suspicious activity!',
        actionLabel: 'Report Suspicious Activity',
        onAction: () {
          _tabController.animateTo(1);
        },
      );
    }

    return Column(
      children: _reports.map((report) => _buildReportItemCard(report)).toList(),
    );
  }

  Widget _buildReportItemCard(CommunityReport report) {
    final color = _getCategoryColor(report.category);
    final icon = _getCategoryIcon(report.category);
    final badgeType = _getStatusBadgeType(report.status);

    return Padding(
      padding: const EdgeInsets.only(bottom: 12.0),
      child: InkWell(
        onTap: () => _showReportDetailModal(report),
        borderRadius: BorderRadius.circular(12),
        child: CyberShieldCard(
          padding: const EdgeInsets.all(14),
          borderColor: report.isVerified
              ? AppColors.danger.withValues(alpha: 0.5)
              : AppColors.cardBorder,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Header: Category chip + Status badge
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Row(
                    children: [
                      Container(
                        padding: const EdgeInsets.all(6),
                        decoration: BoxDecoration(
                          color: color.withValues(alpha: 0.15),
                          borderRadius: BorderRadius.circular(6),
                        ),
                        child: Icon(icon, color: color, size: 16),
                      ),
                      const SizedBox(width: 8),
                      Text(
                        report.category.toUpperCase(),
                        style: TextStyle(
                          color: color,
                          fontSize: 12,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                      const SizedBox(width: 8),
                      Text(
                        _formatTimestamp(report.createdAt),
                        style: const TextStyle(
                          color: AppColors.textMuted,
                          fontSize: 11,
                        ),
                      ),
                    ],
                  ),
                  CyberBadge(
                    label: report.isVerified ? 'VERIFIED' : report.status,
                    type: badgeType,
                  ),
                ],
              ),
              const SizedBox(height: 10),
              // Target String
              Text(
                report.targetDisplay,
                style: const TextStyle(
                  color: AppColors.textPrimary,
                  fontSize: 14,
                  fontWeight: FontWeight.w700,
                ),
                maxLines: 2,
                overflow: TextOverflow.ellipsis,
              ),
              const SizedBox(height: 4),
              // Title / Reason
              Text(
                report.title,
                style: const TextStyle(
                  color: AppColors.textSecondary,
                  fontSize: 12,
                ),
                maxLines: 2,
                overflow: TextOverflow.ellipsis,
              ),
              if (report.tags.isNotEmpty) ...[
                const SizedBox(height: 8),
                Wrap(
                  spacing: 6,
                  runSpacing: 4,
                  children: report.tags.map((t) {
                    return Container(
                      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                      decoration: BoxDecoration(
                        color: AppColors.surfaceLight,
                        borderRadius: BorderRadius.circular(4),
                        border: Border.all(color: AppColors.cardBorder),
                      ),
                      child: Text(
                        '#$t',
                        style: const TextStyle(color: AppColors.textSecondary, fontSize: 10),
                      ),
                    );
                  }).toList(),
                ),
              ],
              const SizedBox(height: 10),
              // Footer: Reputation details & tap hint
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  if (report.reputation != null)
                    Container(
                      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                      decoration: BoxDecoration(
                        color: (report.reputation!.suspicionScore >= 60
                                ? AppColors.danger
                                : (report.reputation!.suspicionScore >= 30
                                    ? AppColors.warning
                                    : AppColors.safe))
                            .withValues(alpha: 0.12),
                        borderRadius: BorderRadius.circular(6),
                      ),
                      child: Text(
                        'Score: ${report.reputation!.suspicionScore}/100 • ${report.reputation!.distinctReporters} reporters',
                        style: TextStyle(
                          color: report.reputation!.suspicionScore >= 60
                              ? AppColors.danger
                              : (report.reputation!.suspicionScore >= 30
                                  ? AppColors.warning
                                  : AppColors.safe),
                          fontSize: 11,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                    )
                  else
                    const SizedBox.shrink(),
                  const Row(
                    children: [
                      Text(
                        'Inspect Evidence',
                        style: TextStyle(
                          color: AppColors.primary,
                          fontSize: 11,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                      SizedBox(width: 4),
                      Icon(
                        Icons.arrow_forward_ios_rounded,
                        size: 10,
                        color: AppColors.primary,
                      ),
                    ],
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }

  void _showReportDetailModal(CommunityReport report) {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: AppColors.surface,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (ctx) {
        return DraggableScrollableSheet(
          initialChildSize: 0.75,
          minChildSize: 0.4,
          maxChildSize: 0.95,
          expand: false,
          builder: (_, scrollController) {
            return ListView(
              controller: scrollController,
              padding: const EdgeInsets.all(20),
              children: [
                Center(
                  child: Container(
                    width: 40,
                    height: 4,
                    decoration: BoxDecoration(
                      color: AppColors.cardBorder,
                      borderRadius: BorderRadius.circular(2),
                    ),
                  ),
                ),
                const SizedBox(height: 16),
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Row(
                      children: [
                        Icon(
                          _getCategoryIcon(report.category),
                          color: _getCategoryColor(report.category),
                          size: 20,
                        ),
                        const SizedBox(width: 8),
                        Text(
                          '${report.category.toUpperCase()} THREAT REPORT',
                          style: TextStyle(
                            color: _getCategoryColor(report.category),
                            fontSize: 13,
                            fontWeight: FontWeight.w800,
                          ),
                        ),
                      ],
                    ),
                    CyberBadge(
                      label: report.status,
                      type: _getStatusBadgeType(report.status),
                    ),
                  ],
                ),
                const SizedBox(height: 12),
                Text(
                  report.title,
                  style: const TextStyle(
                    color: AppColors.textPrimary,
                    fontSize: 16,
                    fontWeight: FontWeight.w700,
                  ),
                ),
                const SizedBox(height: 6),
                Text(
                  'Target: ${report.targetDisplay}',
                  style: const TextStyle(
                    color: AppColors.primary,
                    fontSize: 13,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                const SizedBox(height: 16),
                const Text(
                  'Report Description',
                  style: TextStyle(
                    color: AppColors.textMuted,
                    fontSize: 12,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                const SizedBox(height: 4),
                Text(
                  report.description.isNotEmpty
                      ? report.description
                      : 'No additional observations provided.',
                  style: const TextStyle(
                    color: AppColors.textSecondary,
                    fontSize: 13,
                    height: 1.4,
                  ),
                ),
                if (report.tags.isNotEmpty) ...[
                  const SizedBox(height: 16),
                  const Text(
                    'Threat Tags',
                    style: TextStyle(
                      color: AppColors.textMuted,
                      fontSize: 12,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  const SizedBox(height: 6),
                  Wrap(
                    spacing: 6,
                    runSpacing: 6,
                    children: report.tags.map((t) {
                      return Chip(
                        label: Text('#$t', style: const TextStyle(fontSize: 11)),
                        backgroundColor: AppColors.surfaceLight,
                        side: const BorderSide(color: AppColors.cardBorder),
                      );
                    }).toList(),
                  ),
                ],
                if (report.reputation != null) ...[
                  const SizedBox(height: 20),
                  const Text(
                    'Aggregated Crowd Reputation',
                    style: TextStyle(
                      color: AppColors.textPrimary,
                      fontSize: 14,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                  const SizedBox(height: 8),
                  _buildReputationResultBanner(report.reputation!),
                ],
                const SizedBox(height: 24),
                ElevatedButton(
                  onPressed: () => Navigator.pop(ctx),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: AppColors.primary,
                    foregroundColor: Colors.white,
                    padding: const EdgeInsets.symmetric(vertical: 14),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(10),
                    ),
                  ),
                  child: const Text('Close'),
                ),
              ],
            );
          },
        );
      },
    );
  }

  // ---------------------------------------------------------------------------
  // Tab 2: Threat Report Submission Form
  // ---------------------------------------------------------------------------

  Widget _buildSubmitTab() {
    return Form(
      key: _formKey,
      child: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          // Banner explanation
          CyberShieldCard(
            borderColor: AppColors.primary.withValues(alpha: 0.3),
            child: const Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Icon(Icons.shield_outlined, color: AppColors.primary, size: 22),
                SizedBox(width: 10),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Community Defense Protocol',
                        style: TextStyle(
                          color: AppColors.textPrimary,
                          fontSize: 14,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                      SizedBox(height: 4),
                      Text(
                        'Your report is validated and cryptographically hashed to protect your identity. Reports contribute to community suspicion metrics without exposing personal details.',
                        style: TextStyle(
                          color: AppColors.textSecondary,
                          fontSize: 12,
                          height: 1.35,
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 16),

          // Quick Presets
          const Text(
            'Quick Simulation Presets',
            style: TextStyle(
              color: AppColors.textMuted,
              fontSize: 12,
              fontWeight: FontWeight.w700,
              letterSpacing: 0.5,
            ),
          ),
          const SizedBox(height: 8),
          SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            child: Row(
              children: _presets.map((p) {
                return Padding(
                  padding: const EdgeInsets.only(right: 8.0),
                  child: ActionChip(
                    avatar: Icon(_getCategoryIcon(p.category), size: 14, color: p.color),
                    label: Text(
                      p.label,
                      style: TextStyle(
                        fontSize: 11,
                        color: p.color,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    backgroundColor: p.color.withValues(alpha: 0.1),
                    side: BorderSide(color: p.color.withValues(alpha: 0.4)),
                    onPressed: () => _applyPreset(p),
                  ),
                );
              }).toList(),
            ),
          ),
          const SizedBox(height: 18),

          // Category Selector
          const Text(
            'Threat Category *',
            style: TextStyle(
              color: AppColors.textPrimary,
              fontSize: 13,
              fontWeight: FontWeight.w600,
            ),
          ),
          const SizedBox(height: 6),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 14),
            decoration: BoxDecoration(
              color: AppColors.surfaceLight,
              borderRadius: BorderRadius.circular(10),
              border: Border.all(color: AppColors.cardBorder),
            ),
            child: DropdownButtonHideUnderline(
              child: DropdownButton<String>(
                value: _formCategory,
                isExpanded: true,
                dropdownColor: AppColors.surface,
                style: const TextStyle(color: AppColors.textPrimary, fontSize: 13),
                items: _availableCategories.map((c) {
                  return DropdownMenuItem(
                    value: c,
                    child: Row(
                      children: [
                        Icon(_getCategoryIcon(c), color: _getCategoryColor(c), size: 18),
                        const SizedBox(width: 10),
                        Text(c.toUpperCase()),
                      ],
                    ),
                  );
                }).toList(),
                onChanged: (val) {
                  if (val != null) {
                    setState(() {
                      _formCategory = val;
                    });
                  }
                },
              ),
            ),
          ),
          const SizedBox(height: 16),

          // Target Input
          Text(
            _formCategory == 'phone'
                ? 'Phone Number *'
                : (_formCategory == 'url'
                    ? 'Target URL *'
                    : (_formCategory == 'email'
                        ? 'Sender Email *'
                        : (_formCategory == 'app' ? 'Package Name *' : 'Target Payload *'))),
            style: const TextStyle(
              color: AppColors.textPrimary,
              fontSize: 13,
              fontWeight: FontWeight.w600,
            ),
          ),
          const SizedBox(height: 6),
          TextFormField(
            controller: _formTargetController,
            style: const TextStyle(color: AppColors.textPrimary, fontSize: 13),
            decoration: InputDecoration(
              hintText: _formCategory == 'phone'
                  ? '+1 (800) 555-0199'
                  : (_formCategory == 'url'
                      ? 'https://example-phish.xyz'
                      : (_formCategory == 'email'
                          ? 'security@fake-support.xyz'
                          : (_formCategory == 'app'
                              ? 'com.fake.bank.app'
                              : 'Enter message or payload text'))),
              hintStyle: const TextStyle(color: AppColors.textMuted, fontSize: 13),
              filled: true,
              fillColor: AppColors.surfaceLight,
              contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
              border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(10),
                borderSide: const BorderSide(color: AppColors.cardBorder),
              ),
              enabledBorder: OutlineInputBorder(
                borderRadius: BorderRadius.circular(10),
                borderSide: const BorderSide(color: AppColors.cardBorder),
              ),
            ),
            validator: (v) {
              if (v == null || v.trim().isEmpty) {
                return 'Please provide a valid threat target.';
              }
              return null;
            },
          ),
          const SizedBox(height: 16),

          // Title Input
          const Text(
            'Threat Title / Summary *',
            style: TextStyle(
              color: AppColors.textPrimary,
              fontSize: 13,
              fontWeight: FontWeight.w600,
            ),
          ),
          const SizedBox(height: 6),
          TextFormField(
            controller: _formTitleController,
            style: const TextStyle(color: AppColors.textPrimary, fontSize: 13),
            decoration: InputDecoration(
              hintText: 'e.g. Fake Bank Account Suspension Scam',
              hintStyle: const TextStyle(color: AppColors.textMuted, fontSize: 13),
              filled: true,
              fillColor: AppColors.surfaceLight,
              contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
              border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(10),
                borderSide: const BorderSide(color: AppColors.cardBorder),
              ),
              enabledBorder: OutlineInputBorder(
                borderRadius: BorderRadius.circular(10),
                borderSide: const BorderSide(color: AppColors.cardBorder),
              ),
            ),
            validator: (v) {
              if (v == null || v.trim().length < 3) {
                return 'Title must be at least 3 characters.';
              }
              return null;
            },
          ),
          const SizedBox(height: 16),

          // Description Input
          const Text(
            'Detailed Observations (Optional)',
            style: TextStyle(
              color: AppColors.textPrimary,
              fontSize: 13,
              fontWeight: FontWeight.w600,
            ),
          ),
          const SizedBox(height: 6),
          TextFormField(
            controller: _formDescriptionController,
            maxLines: 3,
            style: const TextStyle(color: AppColors.textPrimary, fontSize: 13),
            decoration: InputDecoration(
              hintText: 'Describe how the lure operated, what credentials were asked, etc.',
              hintStyle: const TextStyle(color: AppColors.textMuted, fontSize: 13),
              filled: true,
              fillColor: AppColors.surfaceLight,
              contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
              border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(10),
                borderSide: const BorderSide(color: AppColors.cardBorder),
              ),
              enabledBorder: OutlineInputBorder(
                borderRadius: BorderRadius.circular(10),
                borderSide: const BorderSide(color: AppColors.cardBorder),
              ),
            ),
          ),
          const SizedBox(height: 16),

          // Threat Tags
          const Text(
            'Select Threat Tags',
            style: TextStyle(
              color: AppColors.textPrimary,
              fontSize: 13,
              fontWeight: FontWeight.w600,
            ),
          ),
          const SizedBox(height: 6),
          Wrap(
            spacing: 6,
            runSpacing: 4,
            children: _commonTags.map((tag) {
              final isSelected = _selectedTags.contains(tag);
              return FilterChip(
                label: Text(
                  '#$tag',
                  style: TextStyle(
                    fontSize: 11,
                    color: isSelected ? Colors.white : AppColors.textSecondary,
                    fontWeight: isSelected ? FontWeight.w700 : FontWeight.w500,
                  ),
                ),
                selected: isSelected,
                selectedColor: AppColors.primary,
                backgroundColor: AppColors.surfaceLight,
                side: BorderSide(
                  color: isSelected ? AppColors.primary : AppColors.cardBorder,
                ),
                padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                onSelected: (selected) {
                  setState(() {
                    if (selected) {
                      _selectedTags.add(tag);
                    } else {
                      _selectedTags.remove(tag);
                    }
                  });
                },
              );
            }).toList(),
          ),
          const SizedBox(height: 20),

          // Submit Success Banner
          if (_submitSuccessId != null) ...[
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: AppColors.safe.withValues(alpha: 0.1),
                borderRadius: BorderRadius.circular(10),
                border: Border.all(color: AppColors.safe.withValues(alpha: 0.3)),
              ),
              child: Row(
                children: [
                  const Icon(Icons.check_circle_outline_rounded, color: AppColors.safe, size: 20),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      'Report $_submitSuccessId successfully recorded! Thank you for strengthening community defense.',
                      style: const TextStyle(color: AppColors.safe, fontSize: 12, fontWeight: FontWeight.w600),
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 16),
          ],

          // Submit Error Banner
          if (_submitError != null) ...[
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: AppColors.danger.withValues(alpha: 0.1),
                borderRadius: BorderRadius.circular(10),
                border: Border.all(color: AppColors.danger.withValues(alpha: 0.3)),
              ),
              child: Row(
                children: [
                  const Icon(Icons.error_outline_rounded, color: AppColors.danger, size: 20),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      _submitError!,
                      style: const TextStyle(color: AppColors.danger, fontSize: 12),
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 16),
          ],

          // Submit Button
          SizedBox(
            width: double.infinity,
            child: ElevatedButton.icon(
              onPressed: _isSubmitting ? null : _submitReport,
              icon: _isSubmitting
                  ? const SizedBox(
                      width: 18,
                      height: 18,
                      child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white),
                    )
                  : const Icon(Icons.send_rounded, size: 18),
              label: Text(_isSubmitting ? 'Submitting to Network...' : 'Broadcast Threat Report'),
              style: ElevatedButton.styleFrom(
                backgroundColor: AppColors.primary,
                foregroundColor: Colors.white,
                padding: const EdgeInsets.symmetric(vertical: 14),
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(10),
                ),
              ),
            ),
          ),
          const SizedBox(height: 16),

          // Legal / Heuristic Disclaimer
          const Text(
            'Notice: False or malicious reports designed to defame legitimate services are subject to automated rate limiting and rejection. Unverified reports reflect crowd consensus and do not constitute legal or forensic evidence.',
            style: TextStyle(
              color: AppColors.textMuted,
              fontSize: 10,
              fontStyle: FontStyle.italic,
              height: 1.35,
            ),
            textAlign: TextAlign.center,
          ),
        ],
      ),
    );
  }

  String _formatTimestamp(String? isoString) {
    if (isoString == null || isoString.isEmpty) return 'Recent';
    try {
      final dt = DateTime.parse(isoString).toLocal();
      const months = [
        'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
        'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'
      ];
      final month = months[dt.month - 1];
      final day = dt.day;
      final hour = dt.hour.toString().padLeft(2, '0');
      final minute = dt.minute.toString().padLeft(2, '0');
      return '$month $day, $hour:$minute';
    } catch (_) {
      return 'Recent';
    }
  }
}
