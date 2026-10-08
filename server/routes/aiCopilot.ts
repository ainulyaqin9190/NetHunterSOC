/**
 * NetHunterSOC - Phase 8 Grounded AI Copilot & Evidence-Bound Analysis
 * Express Router for Grounded AI Copilot operations
 */

import { Router, Request, Response } from 'express';
import { requireAuth } from '../auth/authMiddleware.ts';
import { aiCopilotService } from '../ai/copilotService.ts';
import { aiContextBuilder } from '../ai/contextBuilder.ts';
import type { AiScopeType, CopilotQueryRequest, PromoteDraftNoteRequest } from '../ai/types.ts';

export const aiCopilotRouter = Router();

// 1. Execute Grounded AI Analysis (Non-Autonomous Assistant)
aiCopilotRouter.post('/analyze', requireAuth, async (req: Request, res: Response) => {
  try {
    const { scope_type, scope_id, action_type, custom_prompt, question } = req.body as CopilotQueryRequest;

    if (!scope_type || !scope_id) {
      res.status(400).json({
        error: 'Missing required parameters: scope_type and scope_id must be provided',
      });
      return;
    }

    const validScopes: AiScopeType[] = ['ALERT', 'HYPOTHESIS', 'EVIDENCE', 'DETECTION', 'GRAPH_ENTITY', 'GLOBAL'];
    if (!validScopes.includes(scope_type)) {
      res.status(400).json({
        error: `Invalid scope_type '${scope_type}'. Must be one of: ${validScopes.join(', ')}`,
      });
      return;
    }

    const analyst = {
      id: req.user?.id,
      username: req.user?.username,
    };

    const analysis = await aiCopilotService.analyze(
      {
        scope_type,
        scope_id,
        action_type,
        custom_prompt: custom_prompt || question,
      },
      analyst
    );

    res.status(200).json({
      success: true,
      analysis,
      structured_response: analysis.structured_response,
    });
  } catch (error) {
    res.status(500).json({
      error: error instanceof Error ? error.message : 'Failed to execute AI analysis',
    });
  }
});

// 1b. Ask Copilot Endpoint (Explicit analyst question)
aiCopilotRouter.post('/ask', requireAuth, async (req: Request, res: Response) => {
  try {
    const { scope_type, scope_id, question, prompt } = req.body as {
      scope_type: AiScopeType;
      scope_id: string;
      question?: string;
      prompt?: string;
    };

    const inquiry = question || prompt;
    if (!scope_type || !scope_id || !inquiry) {
      res.status(400).json({
        error: 'Missing required parameters: scope_type, scope_id, and question must be provided',
      });
      return;
    }

    const validScopes: AiScopeType[] = ['ALERT', 'HYPOTHESIS', 'EVIDENCE', 'DETECTION', 'GRAPH_ENTITY', 'GLOBAL'];
    if (!validScopes.includes(scope_type)) {
      res.status(400).json({
        error: `Invalid scope_type '${scope_type}'. Must be one of: ${validScopes.join(', ')}`,
      });
      return;
    }

    const analyst = {
      id: req.user?.id,
      username: req.user?.username,
    };

    const analysis = await aiCopilotService.ask(
      {
        scope_type,
        scope_id,
        question: inquiry,
      },
      analyst
    );

    res.status(200).json({
      success: true,
      analysis,
      answer: analysis.structured_response?.answer || analysis.response,
      observations: analysis.structured_response?.observations || [],
      supporting_references: analysis.structured_response?.supporting_references || [],
      contradicting_references: analysis.structured_response?.contradicting_references || [],
      missing_information: analysis.structured_response?.missing_information || [],
      limitations: analysis.structured_response?.limitations || [],
      structured_response: analysis.structured_response,
    });
  } catch (error) {
    res.status(500).json({
      error: error instanceof Error ? error.message : 'Failed to process AI question',
    });
  }
});

// 2. Retrieve Past Immutable Analyses (Audit Trail)
aiCopilotRouter.get('/analyses', requireAuth, (req: Request, res: Response) => {
  try {
    const { scope_type, scope_id, limit } = req.query;

    const analyses = aiCopilotService.getAnalyses({
      scope_type: scope_type as AiScopeType | undefined,
      scope_id: scope_id ? String(scope_id) : undefined,
      limit: limit ? Number(limit) : undefined,
    });

    res.status(200).json({
      total: analyses.length,
      analyses,
    });
  } catch (error) {
    res.status(500).json({
      error: error instanceof Error ? error.message : 'Failed to retrieve analyses',
    });
  }
});

// 3. Retrieve Single Analysis Record by ID
aiCopilotRouter.get('/analyses/:id', requireAuth, (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const analysis = aiCopilotService.getAnalysisById(id);

    if (!analysis) {
      res.status(404).json({
        error: `Analysis with ID '${id}' not found`,
      });
      return;
    }

    res.status(200).json({
      success: true,
      analysis,
    });
  } catch (error) {
    res.status(500).json({
      error: error instanceof Error ? error.message : 'Failed to retrieve analysis record',
    });
  }
});

// 4. Inspect Assembled Grounded Context (Transparency for Human Analyst)
aiCopilotRouter.post('/context', requireAuth, (req: Request, res: Response) => {
  try {
    const { scope_type, scope_id } = req.body as { scope_type: AiScopeType; scope_id: string };

    if (!scope_type || !scope_id) {
      res.status(400).json({
        error: 'Missing required parameters: scope_type and scope_id must be provided',
      });
      return;
    }

    const context = aiContextBuilder.buildContext(scope_type, scope_id);

    res.status(200).json({
      success: true,
      context,
    });
  } catch (error) {
    res.status(500).json({
      error: error instanceof Error ? error.message : 'Failed to build grounded context',
    });
  }
});

// 5. Explicit Analyst Promotion: Promote Draft Note to Official Analyst Note
aiCopilotRouter.post('/promote-note', requireAuth, (req: Request, res: Response) => {
  try {
    const { analysis_id, note_text, note_type, scope_type, scope_id } = req.body as PromoteDraftNoteRequest;

    if (!note_text || !scope_type || !scope_id) {
      res.status(400).json({
        error: 'Missing required parameters: note_text, scope_type, and scope_id must be provided',
      });
      return;
    }

    const analyst = {
      id: req.user?.id,
      username: req.user?.username,
    };

    const promotedNote = aiCopilotService.promoteDraftNote(
      {
        analysis_id,
        note_text,
        note_type,
        scope_type,
        scope_id,
      },
      analyst
    );

    res.status(201).json({
      success: true,
      promoted_note: promotedNote,
      message: 'Draft note successfully reviewed and recorded to canonical analyst notes',
    });
  } catch (error) {
    res.status(500).json({
      error: error instanceof Error ? error.message : 'Failed to promote draft note',
    });
  }
});
