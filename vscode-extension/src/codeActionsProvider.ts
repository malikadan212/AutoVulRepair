import * as vscode from 'vscode';
import { DiagnosticManager } from './diagnosticManager';

// Rule-based fixable types (must match commands.ts)
const RULE_BASED_FIXABLE_TYPES = new Set([
  'buffer_overflow',
  'stack_buffer_overflow',
  'heap_buffer_overflow',
  'integer_overflow',
  'integer_underflow',
  'null_pointer_dereference',
  'null_dereference',
  'uninitialized_variable',
  'uninitialized_memory',
  'format_string',
  'format_string_vulnerability',
  'memory_leak',
  'resource_leak',
  'double_free',
  'use_after_free',
  'dangling_pointer',
  'array_out_of_bounds',
  'off_by_one',
  'missing_bounds_check',
  'strcpy_overflow',
  'sprintf_overflow',
  'gets_usage',
  'insecure_function',
  'deprecated_function',
  'unsafe_api',
  'signed_unsigned_mismatch',
  'division_by_zero',
  'missing_return',
  'missing_null_check',
  'unchecked_return_value',
]);

function isRuleBasedFixable(vulnType: string): boolean {
  const normalized = vulnType.toLowerCase().replace(/[\s-]+/g, '_');
  for (const ruleType of RULE_BASED_FIXABLE_TYPES) {
    if (normalized.includes(ruleType) || ruleType.includes(normalized)) {
      return true;
    }
  }
  return false;
}

/**
 * Provides code actions (quick fixes) for vulnerabilities.
 * Shows classification labels (rule-based vs AI) and the Smart Fix action.
 */
export class CodeActionsProvider implements vscode.CodeActionProvider {
  constructor(private diagnosticManager: DiagnosticManager) {}

  provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range,
    context: vscode.CodeActionContext,
    _token: vscode.CancellationToken
  ): vscode.CodeAction[] | undefined {
    const actions: vscode.CodeAction[] = [];

    // Only act on AutoVulRepair diagnostics
    const diagnostics = context.diagnostics.filter((d) => d.source === 'AutoVulRepair');
    if (diagnostics.length === 0) {
      return undefined;
    }

    const vulnerability = this.diagnosticManager.getVulnerability(document.uri, range.start.line);
    if (!vulnerability) {
      return undefined;
    }

    const isRuleBased = isRuleBasedFixable(vulnerability.type) || !!vulnerability.patch;

    // ── Smart Fix (combined workflow) — always at the top ────────────────
    const smartAction = new vscode.CodeAction(
      '⚡ Smart Fix (Rule-Based → AI)',
      vscode.CodeActionKind.QuickFix
    );
    smartAction.command = {
      command: 'autoVulRepair.smartFix',
      title: 'Smart Fix (Rule-Based → AI)',
    };
    smartAction.diagnostics = diagnostics;
    smartAction.isPreferred = true;
    actions.push(smartAction);

    // ── Show classification label ───────────────────────────────────────
    if (isRuleBased) {
      // If a patch already exists, offer View / Apply
      if (vulnerability.patch) {
        const viewAction = new vscode.CodeAction(
          '🔍 View Rule-Based Patch',
          vscode.CodeActionKind.QuickFix
        );
        viewAction.command = {
          command: 'autoVulRepair.viewPatch',
          title: 'View Patch',
          arguments: [document.uri, range.start.line],
        };
        viewAction.diagnostics = diagnostics;
        actions.push(viewAction);

        const applyAction = new vscode.CodeAction(
          '🔧 Apply Rule-Based Patch',
          vscode.CodeActionKind.QuickFix
        );
        applyAction.command = {
          command: 'autoVulRepair.applyPatch',
          title: 'Apply Patch',
          arguments: [document.uri, range.start.line],
        };
        applyAction.diagnostics = diagnostics;
        actions.push(applyAction);
      } else {
        // No patch yet – offer to generate one
        const generateAction = new vscode.CodeAction(
          '🔧 Fix with Rule-Based Patch  (auto-fixable)',
          vscode.CodeActionKind.QuickFix
        );
        generateAction.command = {
          command: 'autoVulRepair.generatePatch',
          title: 'Fix with Rule-Based Patch',
          arguments: [document.uri, range.start.line],
        };
        generateAction.diagnostics = diagnostics;
        actions.push(generateAction);
      }
    }

    // ── AI-Assistance option (labelled appropriately) ───────────────────
    const aiLabel = isRuleBased
      ? '🤖 Fix with AI Assistance  (also available)'
      : '🤖 Fix with AI Assistance  (AI required)';

    const aiAction = new vscode.CodeAction(aiLabel, vscode.CodeActionKind.QuickFix);
    aiAction.command = {
      command: 'autoVulRepair.applyAIPatch',
      title: 'Fix with AI Assistance',
      arguments: [document.uri, range.start.line],
    };
    aiAction.diagnostics = diagnostics;
    actions.push(aiAction);

    return actions;
  }
}
