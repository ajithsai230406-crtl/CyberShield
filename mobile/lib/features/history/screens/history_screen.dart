// Audit History Screen for CyberShield

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
import 'package:cybershield/core/models/history_item.dart';

class HistoryScreen extends StatefulWidget {
  const HistoryScreen({super.key});

  @override
  State<HistoryScreen> createState() => _HistoryScreenState();
}

class _HistoryScreenState extends State<HistoryScreen> {
  bool _isLoading = true;
  String? _errorMessage;
  List<HistoryItem> _scans = [];
  int _totalCount = 0;
  bool _isCloudSource = false;

  // Filter state
  String _selectedType = 'ALL';
  String _selectedClassification = 'ALL';

  static const List<String> _typeFilters = [
    'ALL',
    'URL',
    'SMS',
    'QR',
    'SCREENSHOT',
    'APK',
    'PERMISSIONS',
    'EMAIL',
    'FILE',
  ];

  static const List<String> _classificationFilters = [
    'ALL',
    'Safe',
    'Suspicious',
    'High Risk',
    'Critical',
    'Malicious',
  ];

  @override
  void initState() {
    super.initState();
    _fetchHistory();
  }

  Future<void> _fetchHistory() async {
    setState(() {
      _isLoading = true;
      _errorMessage = null;
    });

    try {
      // Prioritize authenticated user's Cloud Firestore history
      if (FirestoreHistoryService.instance.isAuthenticated) {
        final cloudItems = await FirestoreHistoryService.instance.fetchHistory(
          scanType: _selectedType == 'ALL' ? null : _selectedType,
          classification: _selectedClassification == 'ALL'
              ? null
              : _selectedClassification,
        );

        if (mounted) {
          setState(() {
            _isLoading = false;
            _isCloudSource = true;
            _scans = cloudItems;
            _totalCount = cloudItems.length;
          });
          return;
        }
      }

      // Fallback or unauthenticated: read from backend SQLite API
      final result = await ApiService.getHistory(
        scanType: _selectedType == 'ALL' ? null : _selectedType,
        classification:
            _selectedClassification == 'ALL' ? null : _selectedClassification,
      );

      if (mounted) {
        setState(() {
          _isLoading = false;
          _isCloudSource = false;
          if (result['status'] == 'error') {
            _errorMessage =
                result['message'] ?? 'Could not retrieve history logs';
          } else {
            _totalCount = result['total_count'] as int? ?? 0;
            final list = result['scans'] as List? ?? [];
            _scans = list
                .map((e) =>
                    HistoryItem.fromJson(Map<String, dynamic>.from(e as Map)))
                .toList();
          }
        });
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _isLoading = false;
          _errorMessage = 'Error retrieving history: $e';
        });
      }
    }
  }

  Future<void> _clearAllHistory() async {
    if (_scans.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('No scan records to clear'),
          backgroundColor: AppColors.info,
        ),
      );
      return;
    }

    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: AppColors.surface,
        title: const Text('Clear All Scan History'),
        content: const Text(
          'Are you sure you want to permanently clear all scan records from your cloud history? This action cannot be undone.',
          style: TextStyle(color: AppColors.textSecondary),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('Cancel',
                style: TextStyle(color: AppColors.textMuted)),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(ctx, true),
            style: ElevatedButton.styleFrom(
              backgroundColor: AppColors.danger,
              foregroundColor: Colors.white,
            ),
            child: const Text('Clear All'),
          ),
        ],
      ),
    );

    if (confirmed == true) {
      setState(() {
        _isLoading = true;
      });

      if (_isCloudSource) {
        await FirestoreHistoryService.instance.clearAllHistory();
      }

      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('All scan history records cleared'),
            backgroundColor: AppColors.safe,
          ),
        );
        _fetchHistory();
      }
    }
  }

  Future<void> _deleteItem(HistoryItem item) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: AppColors.surface,
        title: const Text('Delete Scan Record'),
        content: Text(
          'Are you sure you want to permanently remove "${item.scanId}" from your audit history?',
          style: const TextStyle(color: AppColors.textSecondary),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('Cancel',
                style: TextStyle(color: AppColors.textMuted)),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(ctx, true),
            style: ElevatedButton.styleFrom(
              backgroundColor: AppColors.danger,
              foregroundColor: Colors.white,
            ),
            child: const Text('Delete'),
          ),
        ],
      ),
    );

    if (confirmed == true) {
      bool success = false;
      if (_isCloudSource) {
        success = await FirestoreHistoryService.instance.deleteScan(item.id);
      } else {
        success = await ApiService.deleteHistoryItem(item.id);
      }

      if (mounted) {
        if (success) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Scan ${item.scanId} deleted from audit log'),
              backgroundColor: AppColors.safe,
            ),
          );
          _fetchHistory();
        } else {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('Failed to delete scan record'),
              backgroundColor: AppColors.danger,
            ),
          );
        }
      }
    }
  }

  BadgeType _getBadgeType(String classification) {
    switch (classification.toLowerCase()) {
      case 'safe':
        return BadgeType.safe;
      case 'suspicious':
        return BadgeType.warning;
      case 'malicious':
      case 'high risk':
      case 'danger':
        return BadgeType.danger;
      default:
        return BadgeType.info;
    }
  }

  Color _getRiskColor(int score) {
    if (score >= 60) return AppColors.danger;
    if (score >= 30) return AppColors.warning;
    return AppColors.safe;
  }

  IconData _getScanIcon(String scanType) {
    switch (scanType.toUpperCase()) {
      case 'URL':
        return Icons.link_rounded;
      case 'SMS':
        return Icons.sms_rounded;
      case 'QR':
        return Icons.qr_code_2_rounded;
      case 'SCREENSHOT':
        return Icons.image_search_rounded;
      case 'APK':
        return Icons.android_rounded;
      case 'PERMISSIONS':
        return Icons.security_update_warning_rounded;
      case 'EMAIL':
        return Icons.mark_email_read_rounded;
      case 'FILE':
        return Icons.folder_zip_rounded;
      default:
        return Icons.security_rounded;
    }
  }

  Color _getTypeColor(String scanType) {
    switch (scanType.toUpperCase()) {
      case 'URL':
        return const Color(0xFF0A84FF);
      case 'SMS':
        return const Color(0xFF5E5CE6);
      case 'QR':
        return const Color(0xFF30D158);
      case 'SCREENSHOT':
        return const Color(0xFFFF9F0A);
      case 'APK':
        return const Color(0xFFFF453A);
      case 'PERMISSIONS':
        return const Color(0xFFFF9F0A);
      case 'EMAIL':
        return const Color(0xFFBF5AF2);
      case 'FILE':
        return const Color(0xFF64D2FF);
      default:
        return AppColors.primary;
    }
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
      final year = dt.year;
      final hour = dt.hour > 12 ? dt.hour - 12 : (dt.hour == 0 ? 12 : dt.hour);
      final minute = dt.minute.toString().padLeft(2, '0');
      final period = dt.hour >= 12 ? 'PM' : 'AM';
      return '$month $day, $year • $hour:$minute $period';
    } catch (_) {
      return isoString;
    }
  }

  void _showScanDetail(HistoryItem scan) {
    final typeColor = _getTypeColor(scan.scanType);
    final badgeType = _getBadgeType(scan.classification);
    final riskColor = _getRiskColor(scan.riskScore);

    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (ctx) {
        return Container(
          decoration: const BoxDecoration(
            color: AppColors.surface,
            borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
          ),
          padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 20),
          child: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
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
                // Header with badge & scan ID
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Row(
                      children: [
                        Container(
                          padding: const EdgeInsets.all(8),
                          decoration: BoxDecoration(
                            color: typeColor.withValues(alpha: 0.15),
                            borderRadius: BorderRadius.circular(8),
                          ),
                          child: Icon(_getScanIcon(scan.scanType),
                              color: typeColor, size: 20),
                        ),
                        const SizedBox(width: 10),
                        Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              scan.scanType,
                              style: TextStyle(
                                color: typeColor,
                                fontSize: 13,
                                fontWeight: FontWeight.w700,
                              ),
                            ),
                            Text(
                              scan.scanId,
                              style: const TextStyle(
                                color: AppColors.textMuted,
                                fontSize: 11,
                              ),
                            ),
                          ],
                        ),
                      ],
                    ),
                    CyberBadge(
                      label: scan.classification.toUpperCase(),
                      type: badgeType,
                    ),
                  ],
                ),
                const SizedBox(height: 16),
                // Risk Score Banner
                Container(
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: riskColor.withValues(alpha: 0.1),
                    borderRadius: BorderRadius.circular(10),
                    border: Border.all(
                      color: riskColor.withValues(alpha: 0.3),
                    ),
                  ),
                  child: Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      Text(
                        'Threat Risk Score',
                        style: TextStyle(
                          color: riskColor,
                          fontWeight: FontWeight.w600,
                          fontSize: 13,
                        ),
                      ),
                      Text(
                        '${scan.riskScore} / 100',
                        style: TextStyle(
                          color: riskColor,
                          fontWeight: FontWeight.w800,
                          fontSize: 16,
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 16),
                // Target input
                const Text(
                  'Inspected Target / Input',
                  style: TextStyle(
                    color: AppColors.textMuted,
                    fontSize: 11,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                const SizedBox(height: 4),
                SelectableText(
                  scan.target,
                  style: const TextStyle(
                    color: AppColors.textPrimary,
                    fontSize: 13,
                    fontWeight: FontWeight.w500,
                  ),
                ),
                const SizedBox(height: 16),
                // Timestamp
                const Text(
                  'Timestamp',
                  style: TextStyle(
                    color: AppColors.textMuted,
                    fontSize: 11,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                const SizedBox(height: 4),
                Text(
                  _formatTimestamp(scan.timestamp),
                  style: const TextStyle(
                    color: AppColors.textSecondary,
                    fontSize: 12,
                  ),
                ),
                if (scan.summary.isNotEmpty) ...[
                  const SizedBox(height: 16),
                  const Text(
                    'Summary',
                    style: TextStyle(
                      color: AppColors.textMuted,
                      fontSize: 11,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    scan.summary,
                    style: const TextStyle(
                      color: AppColors.textSecondary,
                      fontSize: 13,
                    ),
                  ),
                ],
                // Details (findings/explanation/recommendation if present)
                if (scan.details.isNotEmpty) ...[
                  if (scan.details['explanation'] != null) ...[
                    const SizedBox(height: 16),
                    const Text(
                      'Explanation',
                      style: TextStyle(
                        color: AppColors.textMuted,
                        fontSize: 11,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    const SizedBox(height: 4),
                    Text(
                      scan.details['explanation'].toString(),
                      style: const TextStyle(
                        color: AppColors.textSecondary,
                        fontSize: 12,
                        height: 1.35,
                      ),
                    ),
                  ],
                  if (scan.details['recommendation'] != null) ...[
                    const SizedBox(height: 16),
                    const Text(
                      'Recommendation',
                      style: TextStyle(
                        color: AppColors.textMuted,
                        fontSize: 11,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    const SizedBox(height: 4),
                    Text(
                      scan.details['recommendation'].toString(),
                      style: const TextStyle(
                        color: AppColors.textSecondary,
                        fontSize: 12,
                        height: 1.35,
                      ),
                    ),
                  ],
                  if (scan.details['findings'] is List &&
                      (scan.details['findings'] as List).isNotEmpty) ...[
                    const SizedBox(height: 16),
                    const Text(
                      'Detected Findings',
                      style: TextStyle(
                        color: AppColors.textMuted,
                        fontSize: 11,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    const SizedBox(height: 6),
                    Wrap(
                      spacing: 6,
                      runSpacing: 6,
                      children: (scan.details['findings'] as List).map((f) {
                        return Container(
                          padding: const EdgeInsets.symmetric(
                              horizontal: 8, vertical: 4),
                          decoration: BoxDecoration(
                            color: AppColors.surfaceLight,
                            borderRadius: BorderRadius.circular(6),
                            border: Border.all(color: AppColors.cardBorder),
                          ),
                          child: Text(
                            f.toString(),
                            style: const TextStyle(
                              color: AppColors.textSecondary,
                              fontSize: 11,
                            ),
                          ),
                        );
                      }).toList(),
                    ),
                  ],
                ],
                const SizedBox(height: 24),
                // Actions: Delete & Close
                Row(
                  children: [
                    Expanded(
                      child: OutlinedButton.icon(
                        onPressed: () {
                          Navigator.pop(ctx);
                          _deleteItem(scan);
                        },
                        icon: const Icon(Icons.delete_outline_rounded,
                            size: 16, color: AppColors.danger),
                        label: const Text(
                          'Delete Record',
                          style: TextStyle(color: AppColors.danger),
                        ),
                        style: OutlinedButton.styleFrom(
                          side: const BorderSide(color: AppColors.danger),
                          padding: const EdgeInsets.symmetric(vertical: 12),
                          shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(10),
                          ),
                        ),
                      ),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: ElevatedButton(
                        onPressed: () => Navigator.pop(ctx),
                        style: ElevatedButton.styleFrom(
                          backgroundColor: AppColors.primary,
                          foregroundColor: Colors.white,
                          padding: const EdgeInsets.symmetric(vertical: 12),
                          shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(10),
                          ),
                        ),
                        child: const Text('Close'),
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 16),
              ],
            ),
          ),
        );
      },
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Audit History'),
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_rounded),
          onPressed: () =>
              Navigator.pushReplacementNamed(context, AppRouter.dashboard),
        ),
        actions: [
          if (_scans.isNotEmpty)
            IconButton(
              icon: const Icon(Icons.delete_sweep_rounded, color: AppColors.danger),
              onPressed: _clearAllHistory,
              tooltip: 'Clear All History',
            ),
          IconButton(
            icon: const Icon(Icons.refresh_rounded, color: AppColors.primary),
            onPressed: _fetchHistory,
            tooltip: 'Refresh History',
          ),
          const SizedBox(width: 8),
        ],
      ),
      drawer: const NavDrawer(currentRoute: AppRouter.history),
      body: Column(
        children: [
          _buildFilterBar(),
          Expanded(
            child: RefreshIndicator(
              onRefresh: _fetchHistory,
              color: AppColors.primary,
              backgroundColor: AppColors.surface,
              child: _buildBody(),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildFilterBar() {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
      decoration: const BoxDecoration(
        color: AppColors.surface,
        border: Border(
          bottom: BorderSide(color: AppColors.cardBorder, width: 1),
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Scan Type filter chips
          SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            child: Row(
              children: _typeFilters.map((type) {
                final isSelected = _selectedType == type;
                return Padding(
                  padding: const EdgeInsets.only(right: 6.0),
                  child: FilterChip(
                    label: Text(
                      type,
                      style: TextStyle(
                        fontSize: 11,
                        fontWeight:
                            isSelected ? FontWeight.w700 : FontWeight.w500,
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
                          _selectedType = type;
                        });
                        _fetchHistory();
                      }
                    },
                  ),
                );
              }).toList(),
            ),
          ),
          const SizedBox(height: 6),
          // Classification filter chips
          SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            child: Row(
              children: _classificationFilters.map((cls) {
                final isSelected = _selectedClassification == cls;
                return Padding(
                  padding: const EdgeInsets.only(right: 6.0),
                  child: FilterChip(
                    label: Text(
                      cls,
                      style: TextStyle(
                        fontSize: 11,
                        fontWeight:
                            isSelected ? FontWeight.w700 : FontWeight.w500,
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
                          _selectedClassification = cls;
                        });
                        _fetchHistory();
                      }
                    },
                  ),
                );
              }).toList(),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildBody() {
    if (_isLoading) {
      return Center(
        child: CyberLoadingState(
          title: 'Fetching Audit History...',
          subtitle: _isCloudSource
              ? 'Loading cloud scan records from Firestore'
              : 'Querying persistent inspection records',
        ),
      );
    }

    if (_errorMessage != null) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(24.0),
          child: CyberErrorState(
            title: 'Audit Log Retrieval Failed',
            message: _errorMessage!,
            onRetry: _fetchHistory,
          ),
        ),
      );
    }

    if (_scans.isEmpty) {
      return Center(
        child: CyberEmptyState(
          icon: Icons.history_rounded,
          title: 'No Matching Scans',
          description: _selectedType != 'ALL' || _selectedClassification != 'ALL'
              ? 'No scan records match the current filter criteria.'
              : 'Completed inspections for URLs, SMS, QR codes, screenshots, and APKs will be logged here.',
          actionLabel: _selectedType != 'ALL' || _selectedClassification != 'ALL'
              ? 'Clear Filters'
              : 'Launch Dashboard',
          onAction: () {
            if (_selectedType != 'ALL' || _selectedClassification != 'ALL') {
              setState(() {
                _selectedType = 'ALL';
                _selectedClassification = 'ALL';
              });
              _fetchHistory();
            } else {
              Navigator.pushReplacementNamed(context, AppRouter.dashboard);
            }
          },
        ),
      );
    }

    return ListView.separated(
      padding: const EdgeInsets.fromLTRB(16, 14, 16, 80),
      itemCount: _scans.length + 1,
      separatorBuilder: (context, index) => const SizedBox(height: 10),
      itemBuilder: (context, index) {
        if (index == 0) {
          return Padding(
            padding: const EdgeInsets.only(bottom: 4.0),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Text(
                  '${_scans.length} Recorded Inspections',
                  style: const TextStyle(
                    color: AppColors.textPrimary,
                    fontSize: 14,
                    fontWeight: FontWeight.w700,
                  ),
                ),
                Text(
                  _isCloudSource ? 'Cloud Firestore' : 'Total in DB: $_totalCount',
                  style: const TextStyle(
                    color: AppColors.textMuted,
                    fontSize: 12,
                    fontWeight: FontWeight.w500,
                  ),
                ),
              ],
            ),
          );
        }

        final scan = _scans[index - 1];
        final typeColor = _getTypeColor(scan.scanType);
        final badgeType = _getBadgeType(scan.classification);
        final riskColor = _getRiskColor(scan.riskScore);
        final timestamp = _formatTimestamp(scan.timestamp);

        return CyberShieldCard(
          onTap: () => _showScanDetail(scan),
          borderRadius: 12,
          padding: const EdgeInsets.all(14),
          borderColor: scan.riskScore >= 60
              ? AppColors.danger.withValues(alpha: 0.3)
              : AppColors.cardBorder,
          child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                // Top header: scan type + timestamp + badge
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Row(
                      children: [
                        Container(
                          padding: const EdgeInsets.all(6),
                          decoration: BoxDecoration(
                            color: typeColor.withValues(alpha: 0.15),
                            borderRadius: BorderRadius.circular(6),
                          ),
                          child: Icon(
                            _getScanIcon(scan.scanType),
                            color: typeColor,
                            size: 16,
                          ),
                        ),
                        const SizedBox(width: 8),
                        Text(
                          scan.scanType,
                          style: TextStyle(
                            color: typeColor,
                            fontSize: 12,
                            fontWeight: FontWeight.w700,
                          ),
                        ),
                        const SizedBox(width: 8),
                        Text(
                          timestamp,
                          style: const TextStyle(
                            color: AppColors.textMuted,
                            fontSize: 11,
                          ),
                        ),
                      ],
                    ),
                    CyberBadge(
                      label: scan.classification.toUpperCase(),
                      type: badgeType,
                    ),
                  ],
                ),
                const SizedBox(height: 10),
                // Target string
                Text(
                  scan.target,
                  style: const TextStyle(
                    color: AppColors.textPrimary,
                    fontSize: 13,
                    fontWeight: FontWeight.w600,
                  ),
                  maxLines: 2,
                  overflow: TextOverflow.ellipsis,
                ),
                const SizedBox(height: 8),
                // Bottom row: Risk Score & Tap for details
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Container(
                      padding: const EdgeInsets.symmetric(
                          horizontal: 8, vertical: 2),
                      decoration: BoxDecoration(
                        color: riskColor.withValues(alpha: 0.12),
                        borderRadius: BorderRadius.circular(6),
                      ),
                      child: Text(
                        'Risk: ${scan.riskScore}/100',
                        style: TextStyle(
                          color: riskColor,
                          fontWeight: FontWeight.w700,
                          fontSize: 11,
                        ),
                      ),
                    ),
                    const Row(
                      children: [
                        Text(
                          'View Details',
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
        );
      },
    );
  }
}
