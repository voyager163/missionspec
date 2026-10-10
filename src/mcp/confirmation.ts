import type { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { digestApprovalRequest, parseApprovalRequest, type ApprovalRequest } from '../kernel/authority.js';
import type { ContentDigest } from '../kernel/revisions.js';

export interface McpReviewResponse {
  readonly decision: 'accepted' | 'declined' | 'cancelled' | 'unavailable';
  readonly requestDigest: ContentDigest;
}

/** A transport observation only: the trusted authority broker must issue and persist any grant. */
export async function requestMcpReview(
  server: Server,
  value: ApprovalRequest,
  detail: unknown,
  signal?: AbortSignal,
): Promise<McpReviewResponse> {
  const request = parseApprovalRequest(value);
  const requestDigest = digestApprovalRequest(request);
  const response = (decision: McpReviewResponse['decision']): McpReviewResponse =>
    Object.freeze({ decision, requestDigest });
  const capability = server.getClientCapabilities()?.elicitation;
  const formSupported = capability !== undefined &&
    (Object.keys(capability).length === 0 || capability.form !== undefined);
  if (!formSupported || signal?.aborted) return response('unavailable');
  const rendered = JSON.stringify({ request, detail, requestDigest }, null, 2);
  if (Buffer.byteLength(rendered, 'utf8') > 131_072) return response('unavailable');
  try {
    const answer = await server.elicitInput({
      mode: 'form',
      message: `MissionSpec requests local review of the exact scope below. No secret or credential is requested. Declining changes nothing. This interaction is not organization-verified identity.\n\n${rendered}`,
      requestedSchema: {
        type: 'object',
        properties: {
          decision: {
            type: 'string',
            title: 'Decision for this exact request',
            enum: ['decline', 'approve'],
            default: 'decline',
          },
        },
        required: ['decision'],
      },
    }, { timeout: 120_000, ...(signal === undefined ? {} : { signal }) });
    if (signal?.aborted) return response('cancelled');
    if (answer.action === 'cancel') return response('cancelled');
    if (answer.action !== 'accept') return response('declined');
    if (answer.content?.decision !== 'approve' || Object.keys(answer.content).some((key) => key !== 'decision')) {
      return response('declined');
    }
    return response('accepted');
  } catch {
    return response(signal?.aborted ? 'cancelled' : 'unavailable');
  }
}
