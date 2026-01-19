/**
 * Clerk Webhook Handler
 * Handles user.created, user.updated, and organization membership events
 *
 * Setup instructions:
 * 1. Go to Clerk Dashboard > Webhooks
 * 2. Add endpoint: https://your-domain.com/api/webhooks/clerk
 * 3. Subscribe to: user.created, user.updated, organizationMembership.created
 * 4. Copy the signing secret to CLERK_WEBHOOK_SECRET env var
 */

import { NextRequest, NextResponse } from 'next/server';
import { headers } from 'next/headers';
import { Webhook } from 'svix';
import { sql } from '@/lib/db';
import { logAuditEvent } from '@/lib/db/audit';

// Clerk webhook event types
interface ClerkUserEvent {
  data: {
    id: string;
    email_addresses: Array<{
      id: string;
      email_address: string;
    }>;
    primary_email_address_id: string;
    first_name: string | null;
    last_name: string | null;
    created_at: number;
  };
  object: 'event';
  type: 'user.created' | 'user.updated' | 'user.deleted';
}

interface ClerkMembershipEvent {
  data: {
    id: string;
    organization: {
      id: string;
      name: string;
      slug: string;
    };
    public_user_data: {
      user_id: string;
      identifier: string;
    };
    role: string;
  };
  object: 'event';
  type: 'organizationMembership.created' | 'organizationMembership.updated' | 'organizationMembership.deleted';
}

type WebhookEvent = ClerkUserEvent | ClerkMembershipEvent;

export async function POST(request: NextRequest) {
  // Get the webhook signing secret
  const webhookSecret = process.env.CLERK_WEBHOOK_SECRET;

  if (!webhookSecret) {
    console.error('CLERK_WEBHOOK_SECRET not configured');
    return NextResponse.json(
      { error: 'Webhook not configured' },
      { status: 500 }
    );
  }

  // Get the headers for verification
  const headerPayload = await headers();
  const svixId = headerPayload.get('svix-id');
  const svixTimestamp = headerPayload.get('svix-timestamp');
  const svixSignature = headerPayload.get('svix-signature');

  if (!svixId || !svixTimestamp || !svixSignature) {
    return NextResponse.json(
      { error: 'Missing svix headers' },
      { status: 400 }
    );
  }

  // Get the body
  const payload = await request.text();

  // Verify the webhook signature
  const wh = new Webhook(webhookSecret);
  let event: WebhookEvent;

  try {
    event = wh.verify(payload, {
      'svix-id': svixId,
      'svix-timestamp': svixTimestamp,
      'svix-signature': svixSignature,
    }) as WebhookEvent;
  } catch (err) {
    console.error('Webhook verification failed:', err);
    return NextResponse.json(
      { error: 'Invalid signature' },
      { status: 400 }
    );
  }

  // Handle different event types
  try {
    switch (event.type) {
      case 'user.created':
        await handleUserCreated(event as ClerkUserEvent);
        break;

      case 'user.updated':
        await handleUserUpdated(event as ClerkUserEvent);
        break;

      case 'organizationMembership.created':
        await handleMembershipCreated(event as ClerkMembershipEvent);
        break;

      default:
        console.log(`Unhandled webhook event: ${event.type}`);
    }

    return NextResponse.json({ received: true });
  } catch (error) {
    console.error('Webhook processing error:', error);
    return NextResponse.json(
      { error: 'Processing failed' },
      { status: 500 }
    );
  }
}

/**
 * Handle user.created event
 * Check if user has a pending invitation and apply the invitation role
 */
async function handleUserCreated(event: ClerkUserEvent) {
  const { data } = event;
  const clerkUserId = data.id;
  const primaryEmail = data.email_addresses.find(
    e => e.id === data.primary_email_address_id
  )?.email_address;

  if (!primaryEmail) {
    console.log('User created without email, skipping');
    return;
  }

  const userName = [data.first_name, data.last_name]
    .filter(Boolean)
    .join(' ') || null;

  // Check for pending invitation
  const invitationResult = await sql`
    SELECT
      i.id,
      i.email,
      i.role,
      i.tenant_id,
      i.expires_at,
      i.accepted_at,
      t.clerk_org_id
    FROM user_invitations i
    JOIN tenants t ON i.tenant_id::uuid = t.id
    WHERE LOWER(i.email) = LOWER(${primaryEmail})
      AND i.accepted_at IS NULL
      AND i.expires_at > NOW()
    ORDER BY i.created_at DESC
    LIMIT 1
  `;

  if (invitationResult.length > 0) {
    // User has pending invitation - create user with invitation role
    const invitation = invitationResult[0];

    // Check if user already exists
    const existingUser = await sql`
      SELECT id FROM users WHERE clerk_user_id = ${clerkUserId} LIMIT 1
    `;

    if (existingUser.length === 0) {
      // Create user with invitation role
      const insertResult = await sql`
        INSERT INTO users (
          clerk_user_id,
          email,
          name,
          role,
          tenant_id,
          status,
          is_msp_user,
          created_at,
          updated_at
        ) VALUES (
          ${clerkUserId},
          ${primaryEmail},
          ${userName},
          ${invitation.role},
          ${invitation.tenant_id}::uuid,
          'active',
          ${invitation.role === 'msp_admin'},
          NOW(),
          NOW()
        )
        RETURNING id
      `;

      // Mark invitation as accepted
      await sql`
        UPDATE user_invitations
        SET
          accepted_at = NOW(),
          accepted_by = ${insertResult[0].id}::uuid
        WHERE id = ${invitation.id}::uuid
      `;

      // Log audit event
      await logAuditEvent({
        tenantId: invitation.clerk_org_id,
        actorId: clerkUserId,
        actorEmail: primaryEmail,
        action: 'user.created_via_webhook',
        resourceType: 'user',
        resourceId: insertResult[0].id,
        afterState: {
          email: primaryEmail,
          role: invitation.role,
          source: 'clerk_webhook',
          invitationId: invitation.id,
        },
      });

      console.log(`User ${primaryEmail} created with invitation role: ${invitation.role}`);
    }
  } else {
    // No invitation - just log that user was created in Clerk
    // They will need to be invited to a tenant or accept an invitation later
    console.log(`User ${primaryEmail} created in Clerk without pending invitation`);
  }
}

/**
 * Handle user.updated event
 * Sync email/name changes to database
 */
async function handleUserUpdated(event: ClerkUserEvent) {
  const { data } = event;
  const clerkUserId = data.id;
  const primaryEmail = data.email_addresses.find(
    e => e.id === data.primary_email_address_id
  )?.email_address;

  if (!primaryEmail) return;

  const userName = [data.first_name, data.last_name]
    .filter(Boolean)
    .join(' ') || null;

  // Update user in database if they exist
  await sql`
    UPDATE users
    SET
      email = ${primaryEmail},
      name = ${userName},
      updated_at = NOW()
    WHERE clerk_user_id = ${clerkUserId}
  `;

  console.log(`User ${clerkUserId} updated: ${primaryEmail}`);
}

/**
 * Handle organizationMembership.created event
 * This fires when a user is added to a Clerk organization
 */
async function handleMembershipCreated(event: ClerkMembershipEvent) {
  const { data } = event;
  const clerkUserId = data.public_user_data.user_id;
  const clerkOrgId = data.organization.id;
  const clerkRole = data.role;

  // Find user in our database
  const userResult = await sql`
    SELECT id, role FROM users WHERE clerk_user_id = ${clerkUserId} LIMIT 1
  `;

  if (userResult.length === 0) {
    // User not in database - will be handled by user.created or invitation flow
    return;
  }

  // Find tenant by Clerk org ID
  const tenantResult = await sql`
    SELECT id FROM tenants WHERE clerk_org_id = ${clerkOrgId} LIMIT 1
  `;

  if (tenantResult.length === 0) {
    // Tenant not found - org may not be synced yet
    return;
  }

  const user = userResult[0];
  const tenant = tenantResult[0];

  // IMPORTANT: Only update tenant_id, NOT the role
  // The user's role should come from invitation or database, not Clerk
  await sql`
    UPDATE users
    SET
      tenant_id = ${tenant.id}::uuid,
      updated_at = NOW()
    WHERE id = ${user.id}::uuid
      AND (tenant_id IS NULL OR tenant_id != ${tenant.id}::uuid)
  `;

  console.log(`User ${clerkUserId} linked to tenant ${clerkOrgId} (role preserved: ${user.role})`);
}
