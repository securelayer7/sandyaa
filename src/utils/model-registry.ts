/**
 * Auto-Resolving Model Registry
 *
 * - Claude: Uses CLI tier aliases ('sonnet', 'opus', 'haiku') — the CLI
 *   always resolves to the latest model automatically. No hardcoded IDs.
 * - Gemini: Queries the Generative Language API at startup to discover
 *   the latest model per tier (flash / pro / ultra). Falls back to
 *   static defaults if the API call fails.
 *
 * Nothing to update when new models ship.
 */

import { execSync } from 'child_process';

export type ClaudeTier = 'haiku' | 'sonnet' | 'opus';
export type GeminiTier = 'flash' | 'pro' | 'ultra';
export type ModelTier = ClaudeTier | GeminiTier;

export interface ModelInfo {
  id: string;
  contextWindow: number;
  costPerMTokenInput: number;
  costPerMTokenOutput: number;
}

// ── Claude ─────────────────────────────────────────────────────
// The Claude Code CLI accepts tier aliases directly:
//   --model sonnet  →  resolves to latest sonnet automatically
// So we just pass the tier name as the model ID.

const CLAUDE_MODELS: Record<ClaudeTier, ModelInfo> = {
  haiku: {
    id: 'haiku',            // CLI resolves to latest haiku
    contextWindow: 200_000,
    costPerMTokenInput: 0.80,
    costPerMTokenOutput: 4.00,
  },
  sonnet: {
    id: 'sonnet',           // CLI resolves to latest sonnet
    contextWindow: 200_000,
    costPerMTokenInput: 3.00,
    costPerMTokenOutput: 15.00,
  },
  opus: {
    id: 'opus',             // CLI resolves to latest opus
    contextWindow: 200_000,
    costPerMTokenInput: 15.00,
    costPerMTokenOutput: 75.00,
  },
};

// ── Gemini (static fallbacks — overridden by auto-resolve) ─────

const GEMINI_DEFAULTS: Record<GeminiTier, ModelInfo> = {
  flash: {
    id: 'gemini-2.5-flash',
    contextWindow: 1_000_000,
    costPerMTokenInput: 0.075,
    costPerMTokenOutput: 0.30,
  },
  pro: {
    id: 'gemini-2.5-pro',
    contextWindow: 1_000_000,
    costPerMTokenInput: 1.25,
    costPerMTokenOutput: 5.00,
  },
  ultra: {
    id: 'gemini-2.5-pro',
    contextWindow: 1_000_000,
    costPerMTokenInput: 1.25,
    costPerMTokenOutput: 5.00,
  },
};

// Mutable — gets overwritten by autoResolveGeminiModels()
let geminiModels: Record<GeminiTier, ModelInfo> = { ...GEMINI_DEFAULTS };
let geminiResolved = false;

// ── Gemini auto-resolution ─────────────────────────────────────

/**
 * Query the Gemini API for available models and pick the latest
 * stable model per tier. Call once at startup.
 *
 * Uses GEMINI_API_KEY from env (or the key passed to GeminiExecutor).
 */
export async function autoResolveGeminiModels(apiKey?: string): Promise<void> {
  const key = apiKey || process.env.GEMINI_API_KEY;
  if (!key) {
    console.log('[MODEL REGISTRY] No GEMINI_API_KEY — using static Gemini defaults');
    return;
  }

  try {
    const url = `https://generativelanguage.googleapis.com/v1beta/models?key=${key}`;

    // Use dynamic import for fetch (Node 18+)
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json() as { models: Array<{ name: string; displayName: string; inputTokenLimit?: number }> };
    const models = data.models || [];

    // Filter to stable Gemini models (not preview, not tts, not image-gen)
    const stable = models.filter(m => {
      const name = m.name.replace('models/', '');
      return name.startsWith('gemini-') &&
        !name.includes('preview') &&
        !name.includes('tts') &&
        !name.includes('image') &&
        !name.includes('exp') &&
        !name.includes('lite') &&
        !name.includes('latest');  // aliases, not real IDs
    });

    // Pick the highest-versioned model per tier
    const pick = (keyword: string): string | null => {
      const candidates = stable
        .filter(m => m.name.includes(keyword))
        .map(m => m.name.replace('models/', ''))
        .sort()
        .reverse();
      return candidates[0] || null;
    };

    const flashId = pick('flash');
    const proId = pick('pro');

    if (flashId) {
      geminiModels.flash = { ...GEMINI_DEFAULTS.flash, id: flashId };
      // Update context window if API provides it
      const flashModel = models.find(m => m.name === `models/${flashId}`);
      if (flashModel?.inputTokenLimit) {
        geminiModels.flash.contextWindow = flashModel.inputTokenLimit;
      }
    }

    if (proId) {
      geminiModels.pro = { ...GEMINI_DEFAULTS.pro, id: proId };
      geminiModels.ultra = { ...GEMINI_DEFAULTS.ultra, id: proId }; // ultra aliases pro
      const proModel = models.find(m => m.name === `models/${proId}`);
      if (proModel?.inputTokenLimit) {
        geminiModels.pro.contextWindow = proModel.inputTokenLimit;
        geminiModels.ultra.contextWindow = proModel.inputTokenLimit;
      }
    }

    geminiResolved = true;
    console.log(`[MODEL REGISTRY] Gemini auto-resolved: flash=${geminiModels.flash.id}, pro=${geminiModels.pro.id}`);
  } catch (err: any) {
    console.warn(`[MODEL REGISTRY] Gemini auto-resolve failed (${err.message}) — using static defaults`);
  }
}

// ── Public API ─────────────────────────────────────────────────

export function getClaudeModelId(tier: ClaudeTier): string {
  return CLAUDE_MODELS[tier].id;
}

export function getGeminiModelId(tier: GeminiTier): string {
  return geminiModels[tier].id;
}

export function getClaudeModel(tier: ClaudeTier): ModelInfo {
  return CLAUDE_MODELS[tier];
}

export function getGeminiModel(tier: GeminiTier): ModelInfo {
  return geminiModels[tier];
}

export function getContextWindow(provider: 'claude' | 'gemini', tier: ModelTier): number {
  if (provider === 'claude') {
    return CLAUDE_MODELS[tier as ClaudeTier].contextWindow;
  }
  return geminiModels[tier as GeminiTier].contextWindow;
}

/** Returns the context window for the default Claude model (sonnet). */
export function getDefaultContextWindow(): number {
  return CLAUDE_MODELS.sonnet.contextWindow;
}

/** Build the { tier: modelId } map for Claude (used by executor). */
export function getClaudeModelMap(): Record<ClaudeTier, string> {
  return {
    haiku: CLAUDE_MODELS.haiku.id,
    sonnet: CLAUDE_MODELS.sonnet.id,
    opus: CLAUDE_MODELS.opus.id,
  };
}

/** Build the { tier: modelId } map for Gemini (used by executor). */
export function getGeminiModelMap(): Record<GeminiTier, string> {
  return {
    flash: geminiModels.flash.id,
    pro: geminiModels.pro.id,
    ultra: geminiModels.ultra.id,
  };
}

/** Cost/pricing maps for intelligent-provider-selector. */
export function getClaudeCostMap(): Record<ClaudeTier, number> {
  return {
    haiku: CLAUDE_MODELS.haiku.costPerMTokenInput,
    sonnet: CLAUDE_MODELS.sonnet.costPerMTokenInput,
    opus: CLAUDE_MODELS.opus.costPerMTokenInput,
  };
}

export function getGeminiCostMap(): Record<GeminiTier, number> {
  return {
    flash: geminiModels.flash.costPerMTokenInput,
    pro: geminiModels.pro.costPerMTokenInput,
    ultra: geminiModels.ultra.costPerMTokenInput,
  };
}

export function getClaudeContextWindowMap(): Record<ClaudeTier, number> {
  return {
    haiku: CLAUDE_MODELS.haiku.contextWindow,
    sonnet: CLAUDE_MODELS.sonnet.contextWindow,
    opus: CLAUDE_MODELS.opus.contextWindow,
  };
}

export function getGeminiContextWindowMap(): Record<GeminiTier, number> {
  return {
    flash: geminiModels.flash.contextWindow,
    pro: geminiModels.pro.contextWindow,
    ultra: geminiModels.ultra.contextWindow,
  };
}

/** Whether Gemini models have been auto-resolved from API. */
export function isGeminiResolved(): boolean {
  return geminiResolved;
}
