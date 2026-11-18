// CyberShield Custom Lightweight Markdown Renderer
// Renders headings, bold, italic, code spans, code blocks, bullet points, and lists
// cleanly without external library bloat.

import 'package:flutter/material.dart';
import 'package:cybershield/core/theme/app_theme.dart';

class CyberMarkdownView extends StatelessWidget {
  final String data;
  final TextStyle? baseStyle;
  final Color? primaryColor;
  final bool selectable;

  const CyberMarkdownView({
    super.key,
    required this.data,
    this.baseStyle,
    this.primaryColor,
    this.selectable = true,
  });

  @override
  Widget build(BuildContext context) {
    final effectiveBase = baseStyle ??
        const TextStyle(
          color: AppColors.textPrimary,
          fontSize: 13,
          height: 1.45,
        );
    final accent = primaryColor ?? AppColors.primary;

    final blocks = _parseMarkdownBlocks(data);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      mainAxisSize: MainAxisSize.min,
      children: blocks.map((block) => _buildBlock(block, effectiveBase, accent)).toList(),
    );
  }

  Widget _buildBlock(_MarkdownBlock block, TextStyle baseStyle, Color accent) {
    switch (block.type) {
      case _BlockType.header1:
        return Padding(
          padding: const EdgeInsets.only(top: 8.0, bottom: 4.0),
          child: Text(
            block.text,
            style: baseStyle.copyWith(
              fontSize: (baseStyle.fontSize ?? 13) + 4,
              fontWeight: FontWeight.w900,
              color: accent,
            ),
          ),
        );
      case _BlockType.header2:
        return Padding(
          padding: const EdgeInsets.only(top: 6.0, bottom: 3.0),
          child: Text(
            block.text,
            style: baseStyle.copyWith(
              fontSize: (baseStyle.fontSize ?? 13) + 2,
              fontWeight: FontWeight.w800,
              color: AppColors.textPrimary,
            ),
          ),
        );
      case _BlockType.header3:
        return Padding(
          padding: const EdgeInsets.only(top: 5.0, bottom: 2.0),
          child: Text(
            block.text,
            style: baseStyle.copyWith(
              fontSize: (baseStyle.fontSize ?? 13) + 1,
              fontWeight: FontWeight.w700,
              color: accent,
            ),
          ),
        );
      case _BlockType.codeBlock:
        return Container(
          width: double.infinity,
          margin: const EdgeInsets.symmetric(vertical: 6.0),
          padding: const EdgeInsets.all(10.0),
          decoration: BoxDecoration(
            color: AppColors.surfaceLight,
            borderRadius: BorderRadius.circular(8.0),
            border: Border.all(color: AppColors.cardBorder),
          ),
          child: SelectableText(
            block.text,
            style: TextStyle(
              fontFamily: 'monospace',
              fontSize: (baseStyle.fontSize ?? 13) - 1,
              color: AppColors.primary,
              height: 1.35,
            ),
          ),
        );
      case _BlockType.bullet:
        return Padding(
          padding: const EdgeInsets.only(left: 4.0, bottom: 4.0, top: 1.0),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                '• ',
                style: TextStyle(
                  color: accent,
                  fontWeight: FontWeight.bold,
                  fontSize: baseStyle.fontSize,
                ),
              ),
              Expanded(
                child: _buildInlineRichText(block.text, baseStyle, accent),
              ),
            ],
          ),
        );
      case _BlockType.numbered:
        return Padding(
          padding: const EdgeInsets.only(left: 4.0, bottom: 4.0, top: 1.0),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                '${block.prefix} ',
                style: TextStyle(
                  color: accent,
                  fontWeight: FontWeight.w700,
                  fontSize: baseStyle.fontSize,
                ),
              ),
              Expanded(
                child: _buildInlineRichText(block.text, baseStyle, accent),
              ),
            ],
          ),
        );
      case _BlockType.paragraph:
        return Padding(
          padding: const EdgeInsets.only(bottom: 5.0),
          child: _buildInlineRichText(block.text, baseStyle, accent),
        );
    }
  }

  Widget _buildInlineRichText(String text, TextStyle baseStyle, Color accent) {
    final spans = _parseInlineSpans(text, baseStyle, accent);
    if (selectable) {
      return SelectableText.rich(
        TextSpan(children: spans),
      );
    }
    return RichText(
      text: TextSpan(children: spans),
    );
  }

  List<_MarkdownBlock> _parseMarkdownBlocks(String raw) {
    final lines = raw.split('\n');
    final blocks = <_MarkdownBlock>[];

    bool inCodeBlock = false;
    final codeBuffer = StringBuffer();

    for (int i = 0; i < lines.length; i++) {
      final line = lines[i];
      final trimmed = line.trim();

      if (trimmed.startsWith('```')) {
        if (inCodeBlock) {
          blocks.add(_MarkdownBlock(type: _BlockType.codeBlock, text: codeBuffer.toString().trimRight()));
          codeBuffer.clear();
          inCodeBlock = false;
        } else {
          inCodeBlock = true;
          codeBuffer.clear();
        }
        continue;
      }

      if (inCodeBlock) {
        codeBuffer.writeln(line);
        continue;
      }

      if (trimmed.isEmpty) {
        continue;
      }

      if (trimmed.startsWith('### ')) {
        blocks.add(_MarkdownBlock(type: _BlockType.header3, text: trimmed.substring(4)));
      } else if (trimmed.startsWith('## ')) {
        blocks.add(_MarkdownBlock(type: _BlockType.header2, text: trimmed.substring(3)));
      } else if (trimmed.startsWith('# ')) {
        blocks.add(_MarkdownBlock(type: _BlockType.header1, text: trimmed.substring(2)));
      } else if (trimmed.startsWith('- ') || trimmed.startsWith('* ') || trimmed.startsWith('• ')) {
        blocks.add(_MarkdownBlock(type: _BlockType.bullet, text: trimmed.substring(2)));
      } else if (RegExp(r'^\d+\.\s').hasMatch(trimmed)) {
        final match = RegExp(r'^(\d+\.)\s+(.*)$').firstMatch(trimmed);
        if (match != null) {
          blocks.add(_MarkdownBlock(
            type: _BlockType.numbered,
            prefix: match.group(1),
            text: match.group(2) ?? '',
          ));
        } else {
          blocks.add(_MarkdownBlock(type: _BlockType.paragraph, text: trimmed));
        }
      } else {
        blocks.add(_MarkdownBlock(type: _BlockType.paragraph, text: line));
      }
    }

    if (inCodeBlock && codeBuffer.isNotEmpty) {
      blocks.add(_MarkdownBlock(type: _BlockType.codeBlock, text: codeBuffer.toString().trimRight()));
    }

    return blocks;
  }

  List<InlineSpan> _parseInlineSpans(String text, TextStyle baseStyle, Color accent) {
    final spans = <InlineSpan>[];
    // Tokenize text for **bold**, *italic*, and `code`
    final regex = RegExp(r'(\*\*[^*]+\*\*|\*[^*]+\*|`[^`]+`)');
    int lastIndex = 0;

    for (final match in regex.allMatches(text)) {
      if (match.start > lastIndex) {
        spans.add(TextSpan(
          text: text.substring(lastIndex, match.start),
          style: baseStyle,
        ));
      }

      final matchedText = match.group(0)!;
      if (matchedText.startsWith('**') && matchedText.endsWith('**')) {
        spans.add(TextSpan(
          text: matchedText.substring(2, matchedText.length - 2),
          style: baseStyle.copyWith(
            fontWeight: FontWeight.bold,
            color: AppColors.textPrimary,
          ),
        ));
      } else if (matchedText.startsWith('*') && matchedText.endsWith('*')) {
        spans.add(TextSpan(
          text: matchedText.substring(1, matchedText.length - 1),
          style: baseStyle.copyWith(
            fontStyle: FontStyle.italic,
          ),
        ));
      } else if (matchedText.startsWith('`') && matchedText.endsWith('`')) {
        spans.add(WidgetSpan(
          alignment: PlaceholderAlignment.middle,
          child: Container(
            padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 1),
            margin: const EdgeInsets.symmetric(horizontal: 2),
            decoration: BoxDecoration(
              color: AppColors.surfaceLight,
              borderRadius: BorderRadius.circular(4),
              border: Border.all(color: AppColors.cardBorder, width: 0.8),
            ),
            child: Text(
              matchedText.substring(1, matchedText.length - 1),
              style: TextStyle(
                fontFamily: 'monospace',
                fontSize: (baseStyle.fontSize ?? 13) - 1.5,
                color: accent,
                fontWeight: FontWeight.w600,
              ),
            ),
          ),
        ));
      }

      lastIndex = match.end;
    }

    if (lastIndex < text.length) {
      spans.add(TextSpan(
        text: text.substring(lastIndex),
        style: baseStyle,
      ));
    }

    return spans;
  }
}

enum _BlockType {
  paragraph,
  header1,
  header2,
  header3,
  codeBlock,
  bullet,
  numbered,
}

class _MarkdownBlock {
  final _BlockType type;
  final String text;
  final String? prefix;

  _MarkdownBlock({
    required this.type,
    required this.text,
    this.prefix,
  });
}
