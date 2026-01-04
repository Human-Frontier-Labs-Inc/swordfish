import { auth } from '@clerk/nextjs/server';
import { NextResponse } from 'next/server';

// GET /api/tenants - Get all accessible tenants
export async function GET() {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // For now, return mock data
    // In production, this would query the database based on user's role
    const tenants = [
      {
        id: orgId || 'tenant_1',
        clerkOrgId: orgId || 'org_1',
        name: 'Demo Organization',
        domain: 'demo.swordfish.io',
        plan: 'pro',
      },
    ];

    return NextResponse.json(tenants);
  } catch (error) {
    console.error('Error fetching tenants:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

// POST /api/tenants - Create a new tenant
export async function POST(request: Request) {
  try {
    const { userId, orgRole } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Only MSP admins can create tenants
    if (orgRole !== 'org:admin') {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
    }

    const body = await request.json();
    const { name, domain, plan } = body;

    if (!name) {
      return NextResponse.json(
        { error: 'Name is required' },
        { status: 400 }
      );
    }

    // For now, return mock created tenant
    // In production, this would insert into the database
    const tenant = {
      id: `tenant_${Date.now()}`,
      clerkOrgId: null, // Will be set when Clerk org is created
      name,
      domain: domain || null,
      plan: plan || 'starter',
      status: 'active',
      createdAt: new Date().toISOString(),
    };

    return NextResponse.json(tenant, { status: 201 });
  } catch (error) {
    console.error('Error creating tenant:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
