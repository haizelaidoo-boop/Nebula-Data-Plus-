import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import argon2 from 'argon2';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import { z } from 'zod';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { PrismaClient, Prisma } from '@prisma/client';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const prisma = new PrismaClient();
const isProd = process.env.NODE_ENV === 'production';
const PORT = Number(process.env.PORT || 3000);
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY || '';
const PAYSTACK_PUBLIC_KEY = process.env.PAYSTACK_PUBLIC_KEY || '';
const WHATSAPP_WEBHOOK_URL = process.env.WHATSAPP_WEBHOOK_URL || '';
const SMS_WEBHOOK_URL = process.env.SMS_WEBHOOK_URL || '';
const WHATSAPP_PHONE_NUMBER_ID = process.env.WHATSAPP_PHONE_NUMBER_ID || '';
const WHATSAPP_ACCESS_TOKEN = process.env.WHATSAPP_ACCESS_TOKEN || '';
const WHATSAPP_API_VERSION = process.env.WHATSAPP_API_VERSION || 'v23.0';
const WHATSAPP_DELIVERY_TEMPLATE = process.env.WHATSAPP_DELIVERY_TEMPLATE || '';
const WHATSAPP_TEMPLATE_LANGUAGE = process.env.WHATSAPP_TEMPLATE_LANGUAGE || 'en_US';
const HUBTEL_SMS_URL = process.env.HUBTEL_SMS_URL || '';
const HUBTEL_CLIENT_ID = process.env.HUBTEL_CLIENT_ID || '';
const HUBTEL_CLIENT_SECRET = process.env.HUBTEL_CLIENT_SECRET || '';
const HUBTEL_SENDER_ID = process.env.HUBTEL_SENDER_ID || 'Nebula';
const MTN_VERIFICATION_URL = process.env.MTN_VERIFICATION_URL || '';
const MTN_VERIFICATION_SECRET = process.env.MTN_VERIFICATION_SECRET || '';
const MAX_DELIVERY_ATTEMPTS = Number(process.env.MAX_DELIVERY_ATTEMPTS || 5);
const DELIVERY_LOCK_SECONDS = Number(process.env.DELIVERY_LOCK_SECONDS || 60);
const LOYALTY_POINTS_PER_GHS = 1;
const REFERRAL_REWARD_GHS = 2;
const LOYALTY_REWARDS = [
  { points: 100, credit: 1 },
  { points: 250, credit: 3 },
  { points: 500, credit: 5 },
  { points: 1000, credit: 12 },
  { points: 2500, credit: 30 },
  { points: 5000, credit: 70 }
];
const ORIGIN = process.env.APP_ORIGIN || `http://localhost:${PORT}`;
const COOKIE = process.env.COOKIE_NAME || 'nebula_session';
const JWT_ISSUER = process.env.JWT_ISSUER || 'nebula-data-plus';
const JWT_AUDIENCE = process.env.JWT_AUDIENCE || 'nebula-data-plus-web';
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  throw new Error('JWT_SECRET must be set in .env and be at least 32 characters long.');
}
if (!process.env.DATABASE_URL) {
  throw new Error('DATABASE_URL must be set in .env.');
}
if (process.env.ADMIN_EMAIL && !process.env.ADMIN_PASSWORD_HASH) {
  throw new Error('ADMIN_PASSWORD_HASH must be set when ADMIN_EMAIL is configured.');
}
if (isProd && (!process.env.APP_ORIGIN || process.env.APP_ORIGIN.includes('localhost'))) {
  throw new Error('APP_ORIGIN must be set to the real HTTPS site URL in production.');
}
if (isProd && !PAYSTACK_SECRET_KEY) {
  throw new Error('PAYSTACK_SECRET_KEY must be set in production.');
}

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      baseUri: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'self'"],
      formAction: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", 'https://*.paystack.co'],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com', 'data:'],
      imgSrc: ["'self'", 'data:', 'blob:', 'https:'],
      connectSrc: ["'self'", 'https://*.paystack.co'],
      frameSrc: ["'self'", 'https://*.paystack.co'],
      ...(isProd ? { upgradeInsecureRequests: [] } : {})
    }
  }
}));
app.use(express.json({ limit: '20kb', verify: (req, _res, buf) => { req.rawBody = Buffer.from(buf); } }));
app.use(cookieParser());

// Strict same-origin protection for state-changing browser requests.
app.use((req, res, next) => {
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
    const origin = req.get('origin');
    if (origin && origin !== ORIGIN) return res.status(403).json({ error: 'Invalid request origin.' });
  }
  next();
});

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: 'draft-7', legacyHeaders: false, keyGenerator: req => `${req.ip}:${String(req.body?.identifier || '').trim().toLowerCase().slice(0,254)}`, message: { error: 'Too many login attempts. Please try again later.' } });
const signupLimiter = rateLimit({ windowMs: 60 * 60 * 1000, limit: 5, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'Too many account creation attempts. Please try again later.' } });
const purchaseLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'Too many purchase attempts. Please try again later.' } });
const generalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 120, standardHeaders: 'draft-7', legacyHeaders: false });
const mtnVerificationLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'Too many MTN checks. Please try again later.' } });

const phoneSchema = z.string().regex(/^0\d{9}$/, 'Enter a valid 10-digit Ghana number.');
const signupSchema = z.object({
  name: z.string().trim().min(2).max(100),
  phone: phoneSchema,
  email: z.string().trim().toLowerCase().email().max(254),
  password: z.string().min(12).max(200)
});
const loginSchema = z.object({ identifier: z.string().trim().min(3).max(254), password: z.string().min(1).max(200) });
const purchaseSchema = z.object({
  network: z.enum(['MTN', 'AirtelTigo', 'Telecel']),
  gb: z.number().positive(),
  phone: phoneSchema,
  method: z.enum(['Paystack', 'Wallet']),
  paymentReference: z.string().trim().max(150).optional()
});
const settingsSchema = z.object({
  name: z.string().trim().min(2).max(80),
  phone: z.string().trim().min(7).max(30),
  announcement: z.string().trim().max(180)
});
const statusSchema = z.object({ status: z.enum(['Pending', 'Processing', 'Completed', 'Failed']), manualDeliveryConfirmed: z.boolean().optional(), confirmationNote: z.string().trim().min(5).max(250).optional() });
const walletFundSchema = z.object({ amount: z.number().min(1).max(5000), reference: z.string().trim().min(3).max(150) });
const referralSchema = z.object({ code: z.string().trim().min(3).max(30) });

const DATA = {
  MTN: [[1, 6], [2, 11], [3, 15], [4, 21], [5, 26], [6, 31], [8, 39], [10, 47], [15, 67], [20, 87]],
  AirtelTigo: [[1, 5], [2, 10], [3, 15], [4, 21], [6, 24]],
  Telecel: [[10, 45], [15, 61], [20, 84], [25, 103], [30, 120], [40, 155]]
};

const DEFAULT_PROVIDERS = [
  { name: 'Primary Delivery Provider', baseUrl: process.env.DELIVERY_PROVIDER_URL || '', secretKey: process.env.DELIVERY_PROVIDER_SECRET || '', active: Boolean(process.env.DELIVERY_PROVIDER_URL), priority: 10 },
  { name: 'Secondary Delivery Provider', baseUrl: process.env.DELIVERY_PROVIDER_URL_2 || '', secretKey: process.env.DELIVERY_PROVIDER_SECRET_2 || '', active: Boolean(process.env.DELIVERY_PROVIDER_URL_2), priority: 20 }
];

async function seedBundles() {
  for (const [network, bundles] of Object.entries(DATA)) {
    for (const [gb, price] of bundles) {
      await prisma.bundle.upsert({ where: { network_gb: { network, gb } }, update: { price, validityDays: 90 }, create: { network, gb, price, validityDays: 90, popular: network === 'MTN' && gb === 10, featured: network === 'MTN' && gb === 10, sortOrder: gb } });
    }
  }
}

async function seedProviders() {
  // Environment values are bootstrap defaults only. Never overwrite an existing
  // provider URL/secret, active flag, priority or performance settings on restart.
  for (const p of DEFAULT_PROVIDERS) {
    const existing = await prisma.provider.findUnique({ where: { name: p.name } });
    if (!existing) {
      await prisma.provider.create({ data: p });
      continue;
    }
    const data = {};
    if (!existing.baseUrl && p.baseUrl) data.baseUrl = p.baseUrl;
    if (!existing.secretKey && p.secretKey) data.secretKey = p.secretKey;
    if (Object.keys(data).length) await prisma.provider.update({ where: { id: existing.id }, data });
  }
}

async function logAudit(userId, action, entity, entityId, details, req) {
  try { await prisma.auditLog.create({ data: { userId: userId || null, action, entity, entityId: entityId || null, details: details ? JSON.stringify(details) : null, ip: req?.ip || null } }); } catch {}
}

async function notifyUser(userId, type, title, message) {
  if (!userId) return;
  try {
    const user = await prisma.user.findUnique({ where: { id: userId }, select: { phone: true, email: true } });
    await prisma.notification.create({ data: { userId, type, title, message } });
    const payload = JSON.stringify({ phone: user?.phone, email: user?.email, type, title, message });
    for (const url of [WHATSAPP_WEBHOOK_URL, SMS_WEBHOOK_URL].filter(Boolean)) { fetch(url, { method:'POST', headers:{'Content-Type':'application/json'}, body:payload }).catch(()=>{}); }
  } catch {}
}

function ghPhone(phone) {
  const raw = String(phone || '').replace(/\D/g, '');
  return raw.startsWith('0') ? `233${raw.slice(1)}` : raw;
}

async function sendWhatsAppDelivery(order) {
  const phone = ghPhone(order.phone);
  const message = `🎉 DATA DELIVERED!\nYour ${order.network} ${Number(order.gb)}GB bundle has been successfully sent to ${order.phone}.\n\nOrder: ${order.id}\nAmount: GH₵${Number(order.price).toFixed(2)}\n\nThank you for using Nebula Data Plus 🪐`;
  if (WHATSAPP_PHONE_NUMBER_ID && WHATSAPP_ACCESS_TOKEN && WHATSAPP_DELIVERY_TEMPLATE) {
    const url = `https://graph.facebook.com/${WHATSAPP_API_VERSION}/${WHATSAPP_PHONE_NUMBER_ID}/messages`;
    const body = { messaging_product:'whatsapp', to:phone, type:'template', template:{ name:WHATSAPP_DELIVERY_TEMPLATE, language:{code:WHATSAPP_TEMPLATE_LANGUAGE}, components:[{type:'body',parameters:[
      {type:'text',text:`${order.network} ${Number(order.gb)}GB`},
      {type:'text',text:order.phone},
      {type:'text',text:order.id},
      {type:'text',text:`GH₵${Number(order.price).toFixed(2)}`}
    ]}] } };
    const r = await fetch(url,{method:'POST',headers:{Authorization:`Bearer ${WHATSAPP_ACCESS_TOKEN}`,'Content-Type':'application/json'},body:JSON.stringify(body)});
    const data = await r.json().catch(()=>({}));
    if (!r.ok) throw new Error(data.error?.message || `WhatsApp HTTP ${r.status}`);
    return { provider:'WhatsApp Cloud API', providerMessageId:data.messages?.[0]?.id || null };
  }
  if (WHATSAPP_WEBHOOK_URL) {
    const r = await fetch(WHATSAPP_WEBHOOK_URL,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({phone:order.phone,type:'Delivery',title:'Data delivered successfully',message})});
    if (!r.ok) throw new Error(`WhatsApp webhook HTTP ${r.status}`);
    return { provider:'WhatsApp webhook', providerMessageId:null };
  }
  throw new Error('WhatsApp is not configured.');
}

async function sendSmsDelivery(order) {
  const phone = ghPhone(order.phone);
  const message = `NEBULA DATA PLUS: ${order.network} ${Number(order.gb)}GB has been delivered to ${order.phone}. Order ${order.id}. Amount GH₵${Number(order.price).toFixed(2)}.`;
  if (HUBTEL_SMS_URL && HUBTEL_CLIENT_ID && HUBTEL_CLIENT_SECRET) {
    const auth = Buffer.from(`${HUBTEL_CLIENT_ID}:${HUBTEL_CLIENT_SECRET}`).toString('base64');
    const url = new URL(HUBTEL_SMS_URL);
    url.searchParams.set('From',HUBTEL_SENDER_ID); url.searchParams.set('To',phone); url.searchParams.set('Content',message);
    const r = await fetch(url,{method:'GET',headers:{Authorization:`Basic ${auth}`}});
    const data = await r.text();
    if (!r.ok) throw new Error(`Hubtel SMS HTTP ${r.status}: ${data.slice(0,300)}`);
    return { provider:'Hubtel SMS', providerMessageId:null };
  }
  if (SMS_WEBHOOK_URL) {
    const r = await fetch(SMS_WEBHOOK_URL,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({phone:order.phone,type:'Delivery',title:'Data delivered successfully',message})});
    if (!r.ok) throw new Error(`SMS webhook HTTP ${r.status}`);
    return { provider:'SMS webhook', providerMessageId:null };
  }
  throw new Error('SMS is not configured.');
}

async function sendDeliveryNotifications(order) {
  if (!order?.id) return;
  const results = [];
  const dispatch = async (channel, fn) => {
    const key = `DELIVERY-${order.id}-${channel}`;
    const existing = await prisma.notificationDispatch.findUnique({where:{dedupeKey:key}});
    if (existing?.status === 'Sent') return true;
    try {
      const sent = await fn();
      await prisma.notificationDispatch.upsert({where:{dedupeKey:key},update:{status:'Sent',provider:sent.provider,providerMessageId:sent.providerMessageId,sentAt:new Date(),lastError:null},create:{orderId:order.id,channel,status:'Sent',provider:sent.provider,providerMessageId:sent.providerMessageId,sentAt:new Date(),dedupeKey:key}});
      results.push({channel,status:'Sent'}); return true;
    } catch(e) {
      await prisma.notificationDispatch.upsert({where:{dedupeKey:key},update:{status:'Failed',attempts:{increment:1},lastError:String(e.message||e).slice(0,500)},create:{orderId:order.id,channel,status:'Failed',attempts:1,lastError:String(e.message||e).slice(0,500),dedupeKey:key}}).catch(()=>{});
      results.push({channel,status:'Failed',error:String(e.message||e)}); return false;
    }
  };
  const whatsappSent = await dispatch('WhatsApp',()=>sendWhatsAppDelivery(order));
  if (!whatsappSent) await dispatch('SMS',()=>sendSmsDelivery(order));
  return results;
}

async function queueDelivery(orderId) {
  const order = await prisma.order.findUnique({ where: { id: orderId } });
  if (!order || order.paymentStatus !== 'Paid' || order.deliveryStatus === 'Delivered') return;
  await prisma.order.updateMany({
    where: { id: orderId, paymentStatus: 'Paid', deliveryStatus: { not: 'Delivered' } },
    data: { status: 'Processing', deliveryStatus: 'Queued', deliveryLockedUntil: null }
  });
  await notifyUser(order.userId, 'Delivery', 'Your data is being delivered', `${order.network} ${Number(order.gb)}GB is being processed for ${maskPhone(order.phone)}.`);
}

async function awardLoyaltyAndReferral(order) {
  if (!order.userId) return;
  const points = Math.max(0, Math.floor(Number(order.price) * LOYALTY_POINTS_PER_GHS));
  if (points <= 0) return;
  try {
    await prisma.$transaction(async (tx) => {
      // Unique orderId makes loyalty awarding idempotent even if delivery confirmation is retried.
      await tx.loyaltyTransaction.create({
        data: { userId: order.userId, orderId: order.id, points, note: `Earned from completed order ${order.id}` }
      });
      await tx.user.update({ where: { id: order.userId }, data: { loyaltyPoints: { increment: points } } });
    });
  } catch (e) {
    if (!(e instanceof Prisma.PrismaClientKnownRequestError && e.code === 'P2002')) throw e;
  }

  // Referral reward is earned only after the referred customer completes a successful delivery.
  try {
    let qualifiedNow = null;
    await prisma.$transaction(async (tx) => {
      const referral = await tx.referral.findUnique({ where: { referredId: order.userId } });
      if (!referral || referral.qualified) return;
      const updated = await tx.referral.updateMany({
        where: { id: referral.id, qualified: false },
        data: { qualified: true, qualifiedAt: new Date(), reward: REFERRAL_REWARD_GHS }
      });
      if (updated.count !== 1) return;
      qualifiedNow = referral.referrerId;
      const reference = `REF-${referral.id}`;
      await tx.walletTransaction.create({ data: { userId: referral.referrerId, type: 'Credit', amount: REFERRAL_REWARD_GHS, reference, note: `Qualified referral reward for ${order.id}` } });
      await tx.user.update({ where: { id: referral.referrerId }, data: { walletBalance: { increment: REFERRAL_REWARD_GHS } } });
    });
    if (qualifiedNow) await notifyUser(qualifiedNow, 'Promotion', 'Referral reward earned', `You earned GH₵${REFERRAL_REWARD_GHS.toFixed(2)} because your referral completed a successful data purchase.`);
  } catch (e) {
    if (!(e instanceof Prisma.PrismaClientKnownRequestError && e.code === 'P2002')) throw e;
  }
}

async function processDelivery(order) {
  // Atomic claim: only one worker/process can move this order into Processing at a time.
  const now = new Date();
  const lockUntil = new Date(now.getTime() + DELIVERY_LOCK_SECONDS * 1000);
  const claim = await prisma.order.updateMany({
    where: {
      id: order.id,
      paymentStatus: 'Paid',
      deliveryStatus: { in: ['Queued', 'Retrying', 'Processing'] },
      deliveryAttempts: { lt: MAX_DELIVERY_ATTEMPTS },
      OR: [{ deliveryStatus: { in: ['Queued', 'Retrying'] } }, { deliveryLockedUntil: { lt: now } }, { deliveryLockedUntil: null }]
    },
    data: { deliveryStatus: 'Processing', status: 'Processing', deliveryLockedUntil: lockUntil }
  });
  if (claim.count !== 1) return;

  const claimed = await prisma.order.findUnique({ where: { id: order.id } });
  if (!claimed || claimed.paymentStatus !== 'Paid' || claimed.deliveryStatus === 'Delivered') return;
  const providers = await prisma.provider.findMany({ where: { active: true }, orderBy: { priority: 'asc' } });
  if (!providers.length) {
    await prisma.order.updateMany({ where: { id: claimed.id, deliveryStatus: 'Processing' }, data: { deliveryStatus: 'Queued', status: 'Processing', deliveryLockedUntil: null, lastDeliveryError: 'No delivery provider configured.' } });
    return;
  }

  const attemptNo = claimed.deliveryAttempts + 1;
  for (const provider of providers) {
    const started = Date.now();
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 15000);
      const response = await fetch(provider.baseUrl, {
        method: 'POST', signal: controller.signal,
        headers: {
          'Content-Type': 'application/json',
          'Idempotency-Key': claimed.deliveryRequestKey,
          ...(provider.secretKey ? { Authorization: `Bearer ${provider.secretKey}` } : {})
        },
        body: JSON.stringify({
          orderId: claimed.id,
          idempotencyKey: claimed.deliveryRequestKey,
          network: claimed.network,
          gb: Number(claimed.gb),
          phone: claimed.phone,
          validityDays: claimed.validityDays,
          amount: Number(claimed.price)
        })
      });
      clearTimeout(timeout);
      const body = await response.text();
      const seconds = Math.max(1, Math.round((Date.now() - started) / 1000));
      await prisma.deliveryAttempt.create({ data: { orderId: claimed.id, attempt: attemptNo, provider: provider.name, status: response.ok ? 'success' : 'failed', response: body.slice(0, 5000), error: response.ok ? null : `HTTP ${response.status}` } });
      await prisma.provider.update({ where: { id: provider.id }, data: { avgSeconds: seconds } });
      if (response.ok) {
        // Finalize only once. A concurrent worker that somehow reaches here gets count=0.
        const finalized = await prisma.order.updateMany({
          where: { id: claimed.id, paymentStatus: 'Paid', deliveryStatus: 'Processing', deliveredAt: null },
          data: { status: 'Completed', deliveryStatus: 'Delivered', deliveryProvider: provider.name, deliveryAttempts: attemptNo, deliveredAt: new Date(), deliveryLockedUntil: null, lastDeliveryError: null }
        });
        if (finalized.count === 1) {
          const updated = await prisma.order.findUnique({ where: { id: claimed.id } });
          await awardLoyaltyAndReferral(updated);
          await notifyUser(updated.userId, 'Delivery', 'Data delivered successfully', `${updated.network} ${Number(updated.gb)}GB has been delivered successfully.`);
          await sendDeliveryNotifications(updated);
        }
        return;
      }
    } catch (e) {
      await prisma.deliveryAttempt.create({ data: { orderId: claimed.id, attempt: attemptNo, provider: provider.name, status: 'failed', error: String(e.message || e).slice(0, 500) } }).catch(() => {});
    }
  }
  const failed = attemptNo >= MAX_DELIVERY_ATTEMPTS;
  const transitioned = await prisma.order.updateMany({
    where: { id: claimed.id, deliveryStatus: 'Processing', deliveredAt: null },
    data: { status: failed ? 'Failed' : 'Processing', deliveryStatus: failed ? 'Failed' : 'Retrying', paymentStatus: failed && claimed.userId ? 'Refunded' : claimed.paymentStatus, deliveryAttempts: attemptNo, deliveryLockedUntil: null, lastDeliveryError: 'All configured delivery providers failed.' }
  });
  if (failed && transitioned.count === 1) {
    if (claimed.userId) {
      const reference = `REFUND-${claimed.id}`;
      const existingRefund = await prisma.walletTransaction.findUnique({ where: { reference } });
      if (!existingRefund) {
        await prisma.$transaction([
          prisma.user.update({ where: { id: claimed.userId }, data: { walletBalance: { increment: Number(claimed.price) } } }),
          prisma.walletTransaction.create({ data: { userId: claimed.userId, type: 'Refund', amount: Number(claimed.price), reference, note: `Automatic refund for failed order ${claimed.id}` } })
        ]);
      }
      await notifyUser(claimed.userId, 'Payment', 'Order failed — refund issued', `Order ${claimed.id} could not be delivered after ${MAX_DELIVERY_ATTEMPTS} attempts. GH₵${Number(claimed.price).toFixed(2)} has been returned to your wallet.`);
    }
  }
}

function startDeliveryWorker() {
  setInterval(async () => {
    try {
      const orders = await prisma.order.findMany({ where: { paymentStatus: 'Paid', deliveryStatus: { in: ['Queued', 'Retrying', 'Processing'] }, deliveryAttempts: { lt: MAX_DELIVERY_ATTEMPTS } }, orderBy: { createdAt: 'asc' }, take: 10 });
      for (const order of orders) await processDelivery(order);
    } catch (e) { console.error('Delivery worker:', e.message); }
  }, 30000);
}


function issueSession(res, user) {
  const token = jwt.sign({ sub: user.id, role: user.role }, JWT_SECRET, {
    expiresIn: '2h', issuer: JWT_ISSUER, audience: JWT_AUDIENCE
  });
  res.cookie(COOKIE, token, {
    httpOnly: true,
    secure: isProd,
    sameSite: 'lax',
    path: '/',
    maxAge: 2 * 60 * 60 * 1000
  });
}

function verifySessionToken(req) {
  const token = req.cookies[COOKIE];
  if (!token) return null;
  try {
    return jwt.verify(token, JWT_SECRET, { issuer: JWT_ISSUER, audience: JWT_AUDIENCE });
  } catch {
    return null;
  }
}

async function auth(req, res, next) {
  const payload = verifySessionToken(req);
  if (!payload?.sub) return res.status(401).json({ error: 'Authentication required.' });
  const user = await prisma.user.findUnique({ where: { id: payload.sub } });
  if (!user) return res.status(401).json({ error: 'User not found.' });
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Administrator privileges required.' });
  next();
}

function publicUser(user) {
  return { id: user.id, name: user.name, phone: user.phone, email: user.email, role: user.role };
}

function maskPhone(phone) {
  return phone.replace(/^(\d{3})\d{3}(\d{4})$/, '$1 XXX $2');
}

function publicOrder(order) {
  return {
    id: order.id,
    network: order.network,
    gb: Number(order.gb),
    price: Number(order.price),
    method: order.method === 'Wallet' ? 'Wallet' : order.method === 'MTN_MoMo' ? 'MTN MoMo' : 'Paystack',
    status: order.status,
    paymentStatus: order.paymentStatus,
    deliveryStatus: order.deliveryStatus,
    validityDays: order.validityDays,
    deliveredAt: order.deliveredAt?.toISOString() || null,
    recipient: maskPhone(order.phone),
    createdAt: order.createdAt.toISOString()
  };
}

function adminOrder(order) {
  return {
    id: order.id,
    userId: order.userId,
    network: order.network,
    gb: Number(order.gb),
    phone: maskPhone(order.phone),
    price: Number(order.price),
    method: order.method === 'Wallet' ? 'Wallet' : order.method === 'MTN_MoMo' ? 'MTN MoMo' : 'Paystack',
    paymentReference: order.paymentReference,
    status: order.status,
    paymentStatus: order.paymentStatus,
    deliveryStatus: order.deliveryStatus,
    validityDays: order.validityDays,
    deliveryProvider: order.deliveryProvider,
    deliveryAttempts: order.deliveryAttempts,
    lastDeliveryError: order.lastDeliveryError,
    createdAt: order.createdAt.toISOString(),
    updatedAt: order.updatedAt.toISOString()
  };
}

async function getSettings() {
  return prisma.setting.upsert({
    where: { id: 1 },
    update: {},
    create: { id: 1, name: "Nebula Data Plus 🪐", phone: '024 223 8345', announcement: 'Affordable Ghana data bundles' }
  });
}

async function bootstrapAdmin() {
  if (!process.env.ADMIN_EMAIL || !process.env.ADMIN_PASSWORD_HASH) return;
  await prisma.user.upsert({
    where: { email: process.env.ADMIN_EMAIL.trim().toLowerCase() },
    update: { passwordHash: process.env.ADMIN_PASSWORD_HASH, role: 'admin', name: 'Administrator' },
    create: {
      name: 'Administrator',
      phone: `9${crypto.randomInt(100000000, 1000000000)}`.slice(0, 10),
      email: process.env.ADMIN_EMAIL.trim().toLowerCase(),
      passwordHash: process.env.ADMIN_PASSWORD_HASH,
      role: 'admin'
    }
  });
}

app.get('/api/health', async (_req, res) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    res.json({ ok: true, database: 'connected' });
  } catch {
    res.status(503).json({ ok: false, database: 'unavailable' });
  }
});

app.post('/api/auth/signup', signupLimiter, async (req, res, next) => {
  try {
    const parsed = signupSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: 'Invalid signup details.', details: parsed.error.flatten().fieldErrors });
    const { name, phone, email, password } = parsed.data;
    const passwordHash = await argon2.hash(password, { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 });
    const user = await prisma.user.create({ data: { name, phone, email, passwordHash, role: 'customer' } });
    issueSession(res, user);
    res.status(201).json({ user: publicUser(user) });
  } catch (error) {
    if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') {
      return res.status(409).json({ error: 'An account with that email or phone already exists.' });
    }
    next(error);
  }
});

app.post('/api/auth/login', loginLimiter, async (req, res, next) => {
  try {
    const parsed = loginSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: 'Invalid login details.' });
    const identifier = parsed.data.identifier.toLowerCase();
    const user = await prisma.user.findFirst({ where: { OR: [{ email: identifier }, { phone: parsed.data.identifier }] } });
    if (!user || !(await argon2.verify(user.passwordHash, parsed.data.password))) return res.status(401).json({ error: 'Incorrect login details.' });
    issueSession(res, user);
    res.json({ user: publicUser(user) });
  } catch (error) { next(error); }
});

app.post('/api/auth/logout', (_req, res) => {
  res.clearCookie(COOKIE, { httpOnly: true, secure: isProd, sameSite: 'lax', path: '/' });
  res.status(204).end();
});

app.get('/api/auth/me', auth, (req, res) => res.json({ user: publicUser(req.user) }));

app.post('/api/mtn/verify', mtnVerificationLimiter, async (req, res, next) => {
  try {
    const parsed = z.object({ phone: phoneSchema }).safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: 'Enter a valid 10-digit Ghana number.' });
    if (!MTN_VERIFICATION_URL) return res.status(503).json({ error: 'MTN number verification is not configured yet. Please contact support.' });

    const headers = { 'Content-Type': 'application/json' };
    if (MTN_VERIFICATION_SECRET) headers.Authorization = `Bearer ${MTN_VERIFICATION_SECRET}`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);
    let response;
    try {
      response = await fetch(MTN_VERIFICATION_URL, { method: 'POST', headers, body: JSON.stringify({ phone: parsed.data.phone, network: 'MTN' }), signal: controller.signal });
    } finally { clearTimeout(timeout); }
    const body = await response.json().catch(() => ({}));
    if (!response.ok) return res.status(502).json({ error: body.message || body.error || 'MTN verification service is unavailable.' });

    const verified = Boolean(body.verified ?? body.eligible ?? body.canReceiveData ?? body.can_receive_data ?? body.data?.verified ?? body.data?.eligible ?? body.data?.canReceiveData);
    const message = body.message || body.data?.message || (verified ? 'Number verified.' : 'This number is not currently eligible for MTN data.');
    res.json({ verified, message });
  } catch (error) {
    if (error?.name === 'AbortError') return res.status(504).json({ error: 'MTN verification timed out. Please try again.' });
    next(error);
  }
});

app.post('/api/orders', purchaseLimiter, async (req, res, next) => {
  try {
    const parsed = purchaseSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: 'Invalid purchase details.' });
    const { network, gb, phone, method, paymentReference } = parsed.data;
    const bundle = await prisma.bundle.findFirst({ where: { network, gb, active: true } });
    if (!bundle) return res.status(400).json({ error: 'This bundle is currently unavailable.' });
    const price = Number(bundle.price);

    const payload = verifySessionToken(req);
    let userId = null;
    if (payload?.sub) {
      const user = await prisma.user.findUnique({ where: { id: payload.sub }, select: { id: true } });
      if (user) userId = user.id;
    }

    if (method === 'Wallet' && !userId) return res.status(401).json({ error: 'Login is required to pay with your wallet.' });

    let order;
    for (let attempt = 0; attempt < 5; attempt++) {
      const id = `NEBULA-${crypto.randomBytes(6).toString('hex').toUpperCase()}`;
      try {
        order = await prisma.$transaction(async tx => {
          if (method === 'Wallet') {
            const debited = await tx.user.updateMany({ where: { id: userId, walletBalance: { gte: price } }, data: { walletBalance: { decrement: price } } });
            if (debited.count !== 1) { const e = new Error('Insufficient wallet balance.'); e.statusCode = 400; throw e; }
          }
          const created = await tx.order.create({
          data: {
            id,
            deliveryRequestKey: `DEL-${crypto.randomUUID()}`,
            userId,
            network,
            gb,
            phone,
            price,
            method: method === 'Wallet' ? 'Wallet' : 'Paystack',
            paymentReference: paymentReference || null,
            paymentStatus: method === 'Wallet' ? 'Paid' : 'Pending',
            paymentProvider: method === 'Wallet' ? 'Wallet' : 'Paystack',
            validityDays: 90,
            status: 'Pending',
            deliveryStatus: 'NotStarted'
          }
        });
          if (method === 'Wallet') await tx.walletTransaction.create({ data: { userId, type: 'Debit', amount: price, reference: `ORDER-${created.id}`, note: `Wallet payment for ${created.id}` } });
          return created;
        });
        if (method === 'Wallet') await queueDelivery(order.id);
        break;
      } catch (error) {
        if (error?.statusCode) return res.status(error.statusCode).json({ error: error.message });
        if (!(error instanceof Prisma.PrismaClientKnownRequestError) || error.code !== 'P2002') throw error;
      }
    }
    if (!order) return res.status(503).json({ error: 'Could not create a unique order number. Please try again.' });

    // IMPORTANT: actual payment verification must happen server-to-server before status becomes Completed.
    res.status(201).json({ order: publicOrder(order) });
  } catch (error) { next(error); }
});

app.get('/api/orders/mine', auth, async (req, res, next) => {
  try {
    const orders = await prisma.order.findMany({ where: { userId: req.user.id }, orderBy: { createdAt: 'desc' } });
    res.json({ orders: orders.map(publicOrder) });
  } catch (error) { next(error); }
});


// Public live delivery feed. This is backed by PostgreSQL order records and is
// pushed to connected browsers over Server-Sent Events (SSE). No screenshot or
// hard-coded delivery figures are used.
const liveDeliveryClients = new Set();
let liveDeliveryLastSignature = '';
let liveDeliveryTimer = null;

function formatLiveOrder(order, now = Date.now()) {
  const start = new Date(order.createdAt).getTime();
  const end = order.deliveredAt ? new Date(order.deliveredAt).getTime() : now;
  const durationMinutes = Math.max(0, Math.round((end - start) / 60000));
  const lane = durationMinutes <= 15 ? 'Fast lane' : 'Standard queue';
  return {
    id: order.id,
    displayId: `#${String(order.id).slice(-6)}`,
    network: order.network,
    gb: Number(order.gb),
    status: order.deliveryStatus === 'Delivered' ? 'Delivered' : 'Processing',
    lane,
    durationMinutes,
    createdAt: new Date(order.createdAt).toISOString(),
    deliveredAt: order.deliveredAt ? new Date(order.deliveredAt).toISOString() : null
  };
}

async function getLiveDeliverySnapshot() {
  const now = Date.now();
  const recentSince = new Date(now - 24 * 60 * 60 * 1000);
  const [active, delivered] = await Promise.all([
    prisma.order.findMany({
      where: { paymentStatus: 'Paid', deliveryStatus: { in: ['Queued', 'Processing', 'Retrying'] } },
      orderBy: { createdAt: 'asc' },
      take: 8,
      select: { id: true, network: true, gb: true, createdAt: true, deliveredAt: true, deliveryStatus: true }
    }),
    prisma.order.findMany({
      where: { deliveryStatus: 'Delivered', deliveredAt: { gte: recentSince } },
      orderBy: { deliveredAt: 'desc' },
      take: 8,
      select: { id: true, network: true, gb: true, createdAt: true, deliveredAt: true, deliveryStatus: true }
    })
  ]);

  const recentDurations = delivered
    .map(o => Math.max(0, Math.round((new Date(o.deliveredAt).getTime() - new Date(o.createdAt).getTime()) / 60000)))
    .filter(n => Number.isFinite(n));
  const averageMinutes = recentDurations.length
    ? Math.round(recentDurations.reduce((a, b) => a + b, 0) / recentDurations.length)
    : null;
  const oldestActiveMinutes = active.length
    ? Math.max(...active.map(o => Math.max(0, Math.round((now - new Date(o.createdAt).getTime()) / 60000))))
    : 0;

  // Current queue health takes precedence over historical averages so the public
  // banner cannot say "moving well" while an active order has already waited too long.
  let condition = 'waiting';
  let headline = 'Live delivery status';
  let message = 'Your delivery activity will appear here in real time.';
  if (oldestActiveMinutes > 60) {
    condition = 'delayed';
    headline = 'Experiencing delays';
    message = `${active.length} order${active.length === 1 ? '' : 's'} currently processing; the oldest is ${oldestActiveMinutes} min old.`;
  } else if (averageMinutes !== null && averageMinutes > 60) {
    condition = 'delayed';
    headline = 'Slightly delayed';
    message = 'Recent deliveries are taking longer than usual.';
  } else if (averageMinutes !== null && averageMinutes <= 15 && oldestActiveMinutes <= 30) {
    condition = 'fast';
    headline = 'Within the hour';
    message = '🔥 Deliveries are moving well.';
  } else if (active.length || averageMinutes !== null) {
    condition = 'normal';
    headline = 'Within the hour';
    message = active.length ? 'Deliveries are moving normally.' : 'Recent deliveries are moving normally.';
  }

  return {
    ok: true,
    updatedAt: new Date(now).toISOString(),
    condition,
    headline,
    message,
    averageMinutes,
    activeCount: active.length,
    oldestActiveMinutes,
    active: active.map(o => formatLiveOrder(o, now)),
    recent: delivered.map(o => formatLiveOrder(o, now))
  };
}

async function broadcastLiveDelivery(force = false) {
  if (!liveDeliveryClients.size) return;
  try {
    const snapshot = await getLiveDeliverySnapshot();
    const signature = JSON.stringify(snapshot);
    if (!force && signature === liveDeliveryLastSignature) return;
    liveDeliveryLastSignature = signature;
    const payload = `event: delivery\ndata: ${JSON.stringify(snapshot)}\n\n`;
    for (const client of [...liveDeliveryClients]) {
      try { client.write(payload); } catch { liveDeliveryClients.delete(client); }
    }
  } catch (error) {
    console.error('Live delivery feed error:', error);
  }
}

function startLiveDeliveryStream() {
  if (liveDeliveryTimer) return;
  liveDeliveryTimer = setInterval(() => broadcastLiveDelivery(), 4000);
}

app.get('/api/live-deliveries', async (_req, res, next) => {
  try { res.json(await getLiveDeliverySnapshot()); } catch (error) { next(error); }
});

app.get('/api/live-deliveries/stream', async (req, res) => {
  res.status(200);
  res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders?.();
  liveDeliveryClients.add(res);
  res.write(': connected\n\n');
  try {
    const snapshot = await getLiveDeliverySnapshot();
    res.write(`event: delivery\ndata: ${JSON.stringify(snapshot)}\n\n`);
  } catch {}
  const keepAlive = setInterval(() => { try { res.write(': ping\n\n'); } catch {} }, 20000);
  req.on('close', () => {
    clearInterval(keepAlive);
    liveDeliveryClients.delete(res);
  });
});

app.get('/api/orders/:id', async (req, res, next) => {
  try {
    const id = req.params.id.toUpperCase().replace(/[^A-Z0-9-]/g, '').slice(0, 40);
    const order = await prisma.order.findUnique({ where: { id } });
    if (!order) return res.status(404).json({ error: 'Order not found.' });
    res.json({ order: publicOrder(order) });
  } catch (error) { next(error); }
});

app.get('/api/payment-config', (_req, res) => {
  res.json({ publicKey: PAYSTACK_PUBLIC_KEY || null });
});

app.post('/api/payments/paystack/initialize', purchaseLimiter, async (req,res,next)=>{
  try { if(!PAYSTACK_SECRET_KEY)return res.status(503).json({error:'Paystack is not configured.'}); const body=z.object({orderId:z.string().trim().min(1).max(40),email:z.string().email().max(254)}).safeParse(req.body); if(!body.success)return res.status(400).json({error:'Invalid payment initialization details.'}); const order=await prisma.order.findUnique({where:{id:body.data.orderId}}); if(!order)return res.status(404).json({error:'Order not found.'}); const token=verifySessionToken(req); if(order.userId && token?.sub!==order.userId)return res.status(403).json({error:'You cannot initialize payment for this order.'}); if(order.paymentStatus==='Paid')return res.status(409).json({error:'Order is already paid.'}); const reference=`NEBULA-${crypto.randomBytes(8).toString('hex')}`; const r=await fetch('https://api.paystack.co/transaction/initialize',{method:'POST',headers:{Authorization:`Bearer ${PAYSTACK_SECRET_KEY}`,'Content-Type':'application/json'},body:JSON.stringify({email:body.data.email,amount:Math.round(Number(order.price)*100),currency:'GHS',reference,metadata:{orderId:order.id,phone:order.phone,network:order.network,bundle:`${Number(order.gb)}GB`},channels:['mobile_money']})}); const data=await r.json().catch(()=>({})); if(!r.ok||!data.status)return res.status(400).json({error:data.message||'Could not initialize Paystack transaction.'}); await prisma.order.update({where:{id:order.id},data:{paymentReference:data.data.reference,paymentStatus:'Pending',paymentProvider:'Paystack'}}); res.json({accessCode:data.data.access_code,reference:data.data.reference}); } catch(e){next(e);} });

app.post('/api/payments/paystack/verify', purchaseLimiter, async (req, res, next) => {
  try {
    if (!PAYSTACK_SECRET_KEY) return res.status(503).json({ error: 'Paystack verification is not configured.' });
    const body = z.object({ orderId: z.string().trim().min(1).max(40), reference: z.string().trim().min(3).max(150) }).safeParse(req.body);
    if (!body.success) return res.status(400).json({ error: 'Invalid payment verification details.' });
    const order = await prisma.order.findUnique({ where: { id: body.data.orderId } });
    if (!order) return res.status(404).json({ error: 'Order not found.' });
    if (order.paymentStatus === 'Paid') return res.json({ verified: true, order: publicOrder(order), alreadyPaid: true });
    if (order.paymentReference && order.paymentReference !== body.data.reference) return res.status(400).json({ error: 'Payment reference does not match this order.' });
    const response = await fetch(`https://api.paystack.co/transaction/verify/${encodeURIComponent(body.data.reference)}`, { headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`, 'Content-Type': 'application/json' } });
    const result = await response.json().catch(() => ({}));
    if (!response.ok || !result.status || result.data?.status !== 'success') return res.status(400).json({ error: result.message || 'Paystack payment could not be verified.' });
    const paidAmount = Number(result.data.amount || 0) / 100;
    const expectedAmount = Number(order.price);
    const paidCurrency = result.data.currency || 'GHS';
    if (paidCurrency !== 'GHS' || Math.abs(paidAmount - expectedAmount) > 0.001) return res.status(400).json({ error: 'Payment amount or currency does not match the order.' });
    const claimed = await prisma.order.updateMany({ where: { id: order.id, paymentStatus: { not: 'Paid' }, paymentReference: body.data.reference }, data: { status: 'Processing', paymentStatus: 'Paid', paymentProvider: 'Paystack', paymentReference: body.data.reference, paidAt: new Date(), deliveryStatus: 'Queued' } });
    if (claimed.count !== 1) { const latest = await prisma.order.findUnique({ where: { id: order.id } }); return res.json({ verified: latest?.paymentStatus === 'Paid', order: latest ? publicOrder(latest) : null, alreadyPaid: true }); }
    const updated = await prisma.order.findUnique({ where: { id: order.id } });
    await logAudit(updated.userId, 'PAYMENT_VERIFIED', 'Order', updated.id, { reference: body.data.reference, amount: paidAmount }, req);
    await notifyUser(updated.userId, 'Payment', 'Payment confirmed', `Payment for ${updated.network} ${Number(updated.gb)}GB has been confirmed.`);
    await queueDelivery(updated.id);
    res.json({ verified: true, order: publicOrder(updated) });
  } catch (error) { next(error); }
});

app.post('/api/payments/paystack/webhook', async (req, res) => {
  try {
    if (!PAYSTACK_SECRET_KEY) return res.status(503).end();
    const signature = req.get('x-paystack-signature') || '';
    const expected = crypto.createHmac('sha512', PAYSTACK_SECRET_KEY).update(req.rawBody || Buffer.from(JSON.stringify(req.body))).digest('hex');
    if (!signature || signature.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return res.status(401).end();
    const event = req.body;
    if (event.event === 'charge.success') {
      const reference = event.data?.reference;
      if (reference?.startsWith('WALLET-')) {
        const userId = event.data?.metadata?.userId;
        const amount = Number(event.data?.amount || 0) / 100;
        if (userId && event.data?.currency === 'GHS' && amount > 0) {
          const existing = await prisma.walletTransaction.findUnique({ where: { reference } });
          if (!existing) {
            await prisma.$transaction([prisma.user.update({ where: { id: userId }, data: { walletBalance: { increment: amount } } }), prisma.walletTransaction.create({ data: { userId, type: 'Credit', amount, reference, note: 'Paystack wallet funding (webhook)' } })]);
            await notifyUser(userId, 'Payment', 'Wallet funded', `GH₵${amount.toFixed(2)} has been added to your wallet.`);
          }
        }
        return res.sendStatus(200);
      }
      const order = reference ? await prisma.order.findUnique({ where: { paymentReference: reference } }) : null;
      if (order && order.paymentStatus !== 'Paid') {
        const amount = Number(event.data?.amount || 0) / 100;
        if (event.data?.currency === 'GHS' && Math.abs(amount - Number(order.price)) < 0.001) {
          const updated = await prisma.order.update({ where: { id: order.id }, data: { paymentStatus: 'Paid', paymentProvider: 'Paystack', paidAt: new Date(), status: 'Processing', deliveryStatus: 'Queued' } });
          await notifyUser(updated.userId, 'Payment', 'Payment confirmed', `Payment for order ${updated.id} has been confirmed.`);
          await queueDelivery(updated.id);
        }
      }
    }
    res.sendStatus(200);
  } catch (error) { console.error('Paystack webhook:', error); res.sendStatus(500); }
});

app.get('/api/settings', async (_req, res, next) => {
  try {
    const settings = await getSettings();
    res.json({ settings: { name: settings.name, phone: settings.phone, announcement: settings.announcement } });
  } catch (error) { next(error); }
});

app.get('/api/admin/settings', auth, requireAdmin, async (_req, res, next) => {
  try {
    const settings = await getSettings();
    res.json({ settings: { name: settings.name, phone: settings.phone, announcement: settings.announcement } });
  } catch (error) { next(error); }
});

app.patch('/api/admin/settings', auth, requireAdmin, async (req, res, next) => {
  try {
    const parsed = settingsSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: 'Invalid website settings.', details: parsed.error.flatten().fieldErrors });
    const settings = await prisma.setting.upsert({ where: { id: 1 }, update: parsed.data, create: { id: 1, ...parsed.data } });
    res.json({ settings: { name: settings.name, phone: settings.phone, announcement: settings.announcement } });
  } catch (error) { next(error); }
});

app.get('/api/admin/orders/export', auth, requireAdmin, async (_req, res, next) => {
  try {
    const orders = await prisma.order.findMany({ orderBy: { createdAt: 'desc' } });
    res.json({ orders: orders.map(adminOrder) });
  } catch (error) { next(error); }
});

app.get('/api/admin/orders', auth, requireAdmin, async (_req, res, next) => {
  try {
    const orders = await prisma.order.findMany({ orderBy: { createdAt: 'desc' } });
    res.json({ orders: orders.map(adminOrder) });
  } catch (error) { next(error); }
});

// Public catalogue and business APIs.
app.get('/api/bundles', generalLimiter, async (_req, res, next) => {
  try { const bundles = await prisma.bundle.findMany({ where: { active: true }, orderBy: [{ network: 'asc' }, { sortOrder: 'asc' }] }); res.json({ bundles }); } catch (e) { next(e); }
});

app.get('/api/analytics/public', generalLimiter, async (_req, res, next) => {
  try { const [orders, completed] = await Promise.all([prisma.order.count(), prisma.order.count({ where: { status: 'Completed' } })]); res.json({ orders, completed, uptime: 'online' }); } catch(e){ next(e); }
});

app.get('/api/wallet', auth, async (req, res, next) => {
  try { const user = await prisma.user.findUnique({ where: { id: req.user.id }, select: { walletBalance: true, loyaltyPoints: true, referralCode: true } }); const txns = await prisma.walletTransaction.findMany({ where: { userId: req.user.id }, orderBy: { createdAt: 'desc' }, take: 30 }); res.json({ balance: Number(user.walletBalance), loyaltyPoints: user.loyaltyPoints, referralCode: user.referralCode, transactions: txns.map(t => ({ ...t, amount: Number(t.amount) })) }); } catch(e){ next(e); }
});

app.post('/api/wallet/initialize', auth, async (req,res,next)=>{
  try { if(!PAYSTACK_SECRET_KEY)return res.status(503).json({error:'Paystack is not configured.'}); const amount=Number(req.body.amount); if(!Number.isFinite(amount)||amount<1||amount>5000)return res.status(400).json({error:'Wallet amount must be between GH₵1 and GH₵5,000.'}); const ref=`WALLET-${crypto.randomUUID()}`; const r=await fetch('https://api.paystack.co/transaction/initialize',{method:'POST',headers:{Authorization:`Bearer ${PAYSTACK_SECRET_KEY}`,'Content-Type':'application/json'},body:JSON.stringify({email:req.user.email,amount:Math.round(amount*100),currency:'GHS',reference:ref,metadata:{type:'wallet_funding',userId:req.user.id},channels:['mobile_money']})}); const data=await r.json().catch(()=>({})); if(!r.ok||!data.status)return res.status(400).json({error:data.message||'Could not initialize wallet payment.'}); res.json({reference:ref,accessCode:data.data.access_code,authorizationUrl:data.data.authorization_url}); } catch(e){next(e);} });

app.post('/api/wallet/verify', auth, async(req,res,next)=>{
  try { if(!PAYSTACK_SECRET_KEY)return res.status(503).json({error:'Paystack is not configured.'}); const reference=String(req.body.reference||'').trim(); if(!reference.startsWith('WALLET-'))return res.status(400).json({error:'Invalid wallet reference.'}); const r=await fetch(`https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`,{headers:{Authorization:`Bearer ${PAYSTACK_SECRET_KEY}`}}); const data=await r.json().catch(()=>({})); if(!r.ok||!data.status||data.data?.status!=='success')return res.status(400).json({error:data.message||'Wallet payment not verified.'}); if(data.data?.metadata?.userId!==req.user.id)return res.status(403).json({error:'Wallet payment ownership could not be verified.'}); const amount=Number(data.data.amount||0)/100; const existing=await prisma.walletTransaction.findUnique({where:{reference}}); if(!existing){ await prisma.$transaction([prisma.user.update({where:{id:req.user.id},data:{walletBalance:{increment:amount}}}),prisma.walletTransaction.create({data:{userId:req.user.id,type:'Credit',amount,reference,note:'Paystack wallet funding'}})]); await notifyUser(req.user.id,'Payment','Wallet funded',`GH₵${amount.toFixed(2)} has been added to your Nebula Data Plus 🪐 wallet.`); } const user=await prisma.user.findUnique({where:{id:req.user.id},select:{walletBalance:true}}); res.json({verified:true,balance:Number(user.walletBalance)}); } catch(e){next(e);} });

app.get('/api/loyalty/rewards', auth, async (req, res, next) => {
  try {
    const user = await prisma.user.findUnique({ where: { id: req.user.id }, select: { loyaltyPoints: true } });
    const points = user?.loyaltyPoints || 0;
    res.json({ points, rewards: LOYALTY_REWARDS.map(r => ({ ...r, eligible: points >= r.points })) });
  } catch (e) { next(e); }
});

app.post('/api/loyalty/redeem', auth, async (req, res, next) => {
  try {
    const points = Number(req.body.points);
    if (!Number.isInteger(points)) return res.status(400).json({ error: 'Select a valid loyalty reward.' });
    const reward = LOYALTY_REWARDS.find(r => r.points === points);
    if (!reward) return res.status(400).json({ error: 'That loyalty reward is not available.' });
    const reference = `LOYALTY-${crypto.randomUUID()}`;
    await prisma.$transaction(async tx => {
      const updated = await tx.user.updateMany({
        where: { id: req.user.id, loyaltyPoints: { gte: reward.points } },
        data: { loyaltyPoints: { decrement: reward.points }, walletBalance: { increment: reward.credit } }
      });
      if (updated.count !== 1) throw Object.assign(new Error('You do not have enough loyalty points for this reward.'), { statusCode: 400 });
      await tx.walletTransaction.create({
        data: { userId: req.user.id, type: 'Credit', amount: reward.credit, reference, note: `Redeemed ${reward.points} loyalty points for GH₵${reward.credit.toFixed(2)} wallet credit` }
      });
    });
    await notifyUser(req.user.id, 'Promotion', 'Loyalty reward redeemed', `${reward.points} points were redeemed for GH₵${reward.credit.toFixed(2)} wallet credit.`);
    res.json({ ok: true, pointsRedeemed: reward.points, credit: reward.credit, reference });
  } catch (e) { if (e?.statusCode) return res.status(e.statusCode).json({ error: e.message }); next(e); }
});

app.get('/api/referrals', auth, async (req, res, next) => {
  try { const refs = await prisma.referral.findMany({ where: { referrerId: req.user.id }, include: { referred: { select: { name: true, createdAt: true } } }, orderBy: { createdAt: 'desc' } }); res.json({ referrals: refs.map(r => ({ name: r.referred.name, reward: Number(r.reward), qualified: r.qualified, qualifiedAt: r.qualifiedAt?.toISOString() || null, createdAt: r.createdAt.toISOString() })) }); } catch(e){ next(e); }
});

app.post('/api/referrals/apply', auth, async (req, res, next) => {
  try {
    const parsed = referralSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: 'Invalid referral code.' });
    const ref = await prisma.user.findUnique({ where: { referralCode: parsed.data.code } });
    if (!ref || ref.id === req.user.id) return res.status(400).json({ error: 'Referral code is not valid.' });
    const existing = await prisma.referral.findUnique({ where: { referredId: req.user.id } });
    if (existing) return res.status(409).json({ error: 'Referral already applied.' });
    await prisma.$transaction([
      prisma.referral.create({ data: { referrerId: ref.id, referredId: req.user.id, reward: 0, qualified: false } }),
      prisma.user.update({ where: { id: req.user.id, referredById: null }, data: { referredById: ref.id } })
    ]);
    res.json({ ok: true, reward: REFERRAL_REWARD_GHS, qualification: 'Reward is released after your first successful paid data delivery.' });
  } catch (e) {
    if (e instanceof Prisma.PrismaClientKnownRequestError && e.code === 'P2002') return res.status(409).json({ error: 'Referral already applied.' });
    next(e);
  }
});

app.get('/api/notifications', auth, async (req,res,next)=>{ try { const ns=await prisma.notification.findMany({where:{userId:req.user.id},orderBy:{createdAt:'desc'},take:50}); res.json({notifications:ns}); } catch(e){next(e);} });
app.patch('/api/notifications/read', auth, async (req,res,next)=>{ try { await prisma.notification.updateMany({where:{userId:req.user.id,read:false},data:{read:true}}); res.json({ok:true}); } catch(e){next(e);} });

app.get('/api/admin/bundles', auth, requireAdmin, async (_req,res,next)=>{ try { const bundles=await prisma.bundle.findMany({orderBy:[{network:'asc'},{sortOrder:'asc'}]}); res.json({bundles}); } catch(e){next(e);} });
app.patch('/api/admin/bundles/:id', auth, requireAdmin, async(req,res,next)=>{ try { const body=z.object({price:z.number().positive(),validityDays:z.number().int().min(1).max(365),active:z.boolean(),popular:z.boolean(),featured:z.boolean(),costPrice:z.number().nonnegative().nullable().optional()}).safeParse(req.body); if(!body.success)return res.status(400).json({error:'Invalid bundle settings.'}); const b=await prisma.bundle.update({where:{id:req.params.id},data:body.data}); await logAudit(req.user.id,'BUNDLE_UPDATED','Bundle',b.id,body.data,req); res.json({bundle:b}); } catch(e){next(e);} });
app.get('/api/admin/providers', auth, requireAdmin, async(_req,res,next)=>{try{const ps=await prisma.provider.findMany({select:{id:true,name:true,active:true,priority:true,successRate:true,avgSeconds:true,baseUrl:true},orderBy:{priority:'asc'}});res.json({providers:ps});}catch(e){next(e);}});
app.patch('/api/admin/providers/:id', auth, requireAdmin, async(req,res,next)=>{try{const body=z.object({active:z.boolean(),priority:z.number().int().min(1).max(999)}).safeParse(req.body);if(!body.success)return res.status(400).json({error:'Invalid provider settings.'});const p=await prisma.provider.update({where:{id:req.params.id},data:body.data});await logAudit(req.user.id,'PROVIDER_UPDATED','Provider',p.id,body.data,req);res.json({provider:{id:p.id,name:p.name,active:p.active,priority:p.priority}});}catch(e){next(e);}});

app.get('/api/admin/analytics', auth, requireAdmin, async (_req,res,next)=>{
  try { const [orders, completed, processing, failed, revenue, paidOrders, bundles] = await Promise.all([prisma.order.count(),prisma.order.count({where:{status:'Completed'}}),prisma.order.count({where:{status:'Processing'}}),prisma.order.count({where:{status:'Failed'}}),prisma.order.aggregate({where:{paymentStatus:'Paid'},_sum:{price:true}}),prisma.order.findMany({where:{paymentStatus:'Paid'},select:{network:true,gb:true,price:true}}),prisma.bundle.findMany({select:{network:true,gb:true,costPrice:true}})]); const costMap=new Map(bundles.map(b=>[`${b.network}:${Number(b.gb)}`,Number(b.costPrice||0)])); const profit=paidOrders.reduce((a,b)=>a+Number(b.price)-(costMap.get(`${b.network}:${Number(b.gb)}`)||0),0); res.json({orders,completed,processing,failed,revenue:Number(revenue._sum.price||0),profit}); } catch(e){next(e);} 
});

app.get('/api/admin/audit-logs', auth, requireAdmin, async (_req,res,next)=>{ try { const logs=await prisma.auditLog.findMany({orderBy:{createdAt:'desc'},take:200}); res.json({logs}); } catch(e){next(e);} });

app.get('/api/admin/reconciliation', auth, requireAdmin, async (_req,res,next)=>{ try { const start=new Date(); start.setHours(0,0,0,0); const end=new Date(start); end.setDate(end.getDate()+1); const paid=await prisma.order.aggregate({where:{paidAt:{gte:start,lt:end},paymentStatus:'Paid',paymentProvider:'Paystack'},_sum:{price:true},_count:{_all:true}}); const orderTotal=Number(paid._sum.price||0); let paystackTotal=0; if(PAYSTACK_SECRET_KEY){ for(let page=1;page<=10;page++){ const r=await fetch(`https://api.paystack.co/transaction?perPage=100&page=${page}`,{headers:{Authorization:`Bearer ${PAYSTACK_SECRET_KEY}`}}); const d=await r.json().catch(()=>({})); if(!r.ok||!d.status)break; const txs=d.data||[]; for(const t of txs){const dt=new Date(t.paid_at||t.created_at); if(t.status==='success'&&t.currency==='GHS'&&dt>=start&&dt<end)paystackTotal+=Number(t.amount||0)/100;} if(txs.length<100)break; } } const difference=Number((paystackTotal-orderTotal).toFixed(2)); res.json({date:start.toISOString().slice(0,10),paystackTotal,orderTotal,difference,status:Math.abs(difference)<0.01?'matched':'review',paidOrders:paid._count._all}); } catch(e){next(e);} });

app.patch('/api/admin/orders/:id/status', auth, requireAdmin, async (req,res,next)=>{
  try {
    const parsed=statusSchema.safeParse(req.body);
    if(!parsed.success)return res.status(400).json({error:'Invalid status.'});
    const existing=await prisma.order.findUnique({where:{id:req.params.id}});
    if(!existing)return res.status(404).json({error:'Order not found.'});
    const { status, manualDeliveryConfirmed, confirmationNote } = parsed.data;
    if (existing.deliveryStatus === 'Delivered' && status !== 'Completed') {
      return res.status(409).json({error:'A delivered order cannot be moved back to another status.'});
    }
    if (status === 'Completed') {
      if (existing.paymentStatus !== 'Paid') return res.status(400).json({error:'An unpaid order cannot be marked Completed.'});
      if (existing.deliveryStatus === 'Delivered') return res.status(409).json({error:'This order is already marked delivered.'});
      if (!manualDeliveryConfirmed || !confirmationNote) return res.status(400).json({error:'Manual delivery confirmation and a confirmation note are required.'});
      const deliveredAt = new Date();
      const order = await prisma.order.update({
        where:{id:existing.id},
        data:{status:'Completed',deliveryStatus:'Delivered',deliveredAt,deliveryProvider:'Manual admin confirmation',deliveryLockedUntil:null,lastDeliveryError:null}
      });
      await logAudit(req.user.id,'ORDER_MANUAL_DELIVERY_CONFIRMED','Order',order.id,{status:'Completed',confirmationNote},req);
      await awardLoyaltyAndReferral(order);
      await notifyUser(order.userId, 'Delivery', 'Data delivered successfully', `${order.network} ${Number(order.gb)}GB has been marked delivered successfully.`);
      await sendDeliveryNotifications(order);
      await broadcastLiveDelivery(true);
      return res.json({order:{id:order.id,status:order.status,deliveryStatus:order.deliveryStatus}});
    }

    if (status === 'Processing' && existing.paymentStatus !== 'Paid') {
      return res.status(400).json({error:'Only paid orders can be moved to Processing.'});
    }
    if (status === 'Pending' && existing.paymentStatus === 'Paid') {
      return res.status(400).json({error:'A paid order cannot be moved back to Pending.'});
    }
    const deliveryStatus = status === 'Failed' ? 'Failed' : status === 'Processing' ? 'Processing' : 'NotStarted';
    const order=await prisma.order.update({
      where:{id:existing.id},
      data:{status,deliveryStatus, ...(status !== 'Completed' ? {deliveredAt:null} : {})}
    });
    await logAudit(req.user.id,'ORDER_STATUS_CHANGED','Order',order.id,{status:order.status,deliveryStatus:order.deliveryStatus},req);
    await broadcastLiveDelivery(true);
    res.json({order:{id:order.id,status:order.status,deliveryStatus:order.deliveryStatus}});
  } catch(error){ if(error instanceof Prisma.PrismaClientKnownRequestError&&error.code==='P2025')return res.status(404).json({error:'Order not found.'}); next(error); }
});

// Generate production-aware SEO files from APP_ORIGIN instead of shipping placeholder domains.
app.get('/robots.txt', (_req, res) => {
  const origin = ORIGIN.replace(/\/$/, '');
  res.type('text/plain').send(`User-agent: *\nAllow: /\nSitemap: ${origin}/sitemap.xml\n`);
});
app.get('/sitemap.xml', (_req, res) => {
  const origin = ORIGIN.replace(/\/$/, '');
  const xml = `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n  <url><loc>${origin}/</loc><changefreq>daily</changefreq><priority>1.0</priority></url>\n</urlset>`;
  res.type('application/xml').send(xml);
});

// Serve the frontend. Admin HTML is not a security boundary; /api/admin/* always enforces role=admin.
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.use((error, _req, res, _next) => {
  console.error(error);
  res.status(500).json({ error: 'An unexpected server error occurred.' });
});

async function start() {
  await prisma.$connect();
  await getSettings();
  await seedBundles();
  await seedProviders();
  await bootstrapAdmin();
  startDeliveryWorker();
  startLiveDeliveryStream();
  const server = app.listen(PORT, () => console.log(`Nebula Data Plus 🪐 running at ${ORIGIN}`));
  const shutdown = async (signal) => {
    console.log(`${signal}: shutting down...`);
    server.close(async () => { await prisma.$disconnect(); process.exit(0); });
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

start().catch(async (error) => {
  console.error('Failed to start Nebula Data Plus:', error);
  await prisma.$disconnect();
  process.exit(1);
});
