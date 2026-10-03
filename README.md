# Anonymous Complaint Portal (Python / Flask)

Features: anonymous complaint registration with optional User ID alias, auto Ticket ID,
categories, status tracking (Pending / In Progress / Resolved / Rejected), admin dashboard
grouped & filtered by category and status. Database via SQLAlchemy (SQLite locally, PostgreSQL on AWS RDS).

## Run locally
    python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
    pip install -r requirements.txt
    python app.py        # http://127.0.0.1:5000  (admin: admin / admin123)

## Environment variables
- DATABASE_URL  e.g. postgresql://user:pass@host:5432/complaints
- SECRET_KEY    long random string
- ADMIN_USER / ADMIN_PASSWORD

## Host on AWS (Elastic Beanstalk + RDS PostgreSQL)
1. Install AWS CLI + EB CLI: `pip install awsebcli`, then `aws configure`.
2. In this folder: `eb init -p python-3.11 complaint-portal --region ap-south-1`
3. Create env: `eb create complaint-env`
4. Create database: AWS Console > RDS > Create database > PostgreSQL (Free tier, db.t3.micro),
   same VPC as the EB env; allow the EB security group on port 5432. Create DB `complaints`.
5. Set config:
   `eb setenv DATABASE_URL=postgresql://USER:PASS@RDS_ENDPOINT:5432/complaints SECRET_KEY=... ADMIN_USER=admin ADMIN_PASSWORD=...`
6. `eb deploy` then `eb open`. Tables are created automatically on first start.

Cost note: EB t3.micro + RDS db.t3.micro are free-tier eligible for 12 months; afterwards roughly $25-30/month. Set an AWS Budget alert. Remove with `eb terminate` and delete the RDS instance.

Alternative: EC2 Ubuntu instance: install python3, clone, `pip install -r requirements.txt`,
run `gunicorn -b 0.0.0.0:80 app:application` behind nginx.

## Secure status check page (/track)

- Lookup is by tracking code only — the alias/User ID search was removed so one
  person's code can never reveal another person's complaints.
- The code is sent by POST, so it never appears in the web address, browser
  history, server logs or referrer headers.
- Code format is validated (10 hex characters) before any database lookup.
- Rate limited to 5 checks per 10 minutes per visitor to stop code guessing.
- Responses are sent with no-store caching, no-referrer and noindex headers.
- All forms carry a CSRF token; session cookies are HttpOnly and SameSite=Lax.
  Set `COOKIE_SECURE=1` in production so cookies are only sent over HTTPS.

Note: the rate limiter is in-memory, so it applies per server process. If you
scale to several instances on AWS, move the counter to Redis (ElastiCache) or
use AWS WAF rate-based rules on /track.
