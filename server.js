require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { z } = require('zod');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 8080;
const DATA_FILE = path.join(__dirname, 'data.json');

/* =========================================================
   REQUIRED ENVIRONMENT VARIABLES
========================================================= */
for (const key of ['JWT_SECRET', 'ADMIN_USERNAME', 'ADMIN_PASSWORD']) {
  if (!process.env[key]) {
    console.error(`❌ Missing ${key} environment variable`);
    process.exit(1);
  }
}

/* =========================================================
   DATA STORAGE
========================================================= */
function emptyData() {
  return {
    users: [],
    loans: [],
    withdrawals: [],
    transactions: [],
    auditLogs: []
  };
}

if (!fs.existsSync(DATA_FILE)) {
  fs.writeFileSync(
    DATA_FILE,
    JSON.stringify(emptyData(), null, 2),
    'utf8'
  );
}

function normalizeUser(user) {
  return {
    ...user,
    balance: Number(user.balance || 0),
    currency: user.currency || 'NGN',
    status: user.status || 'active',
    verificationStatus:
      user.verificationStatus || 'pending',
    verificationNote:
      user.verificationNote || null,
    verifiedAt:
      user.verifiedAt || null,
    updatedAt:
      user.updatedAt ||
      user.createdAt ||
      new Date().toISOString()
  };
}

function readData() {
  try {
    const raw = fs.readFileSync(DATA_FILE, 'utf8');

    if (!raw.trim()) {
      return emptyData();
    }

    const parsed = JSON.parse(raw);

    return {
      users:
        Array.isArray(parsed.users)
          ? parsed.users.map(normalizeUser)
          : [],

      loans:
        Array.isArray(parsed.loans)
          ? parsed.loans
          : [],

      withdrawals:
        Array.isArray(parsed.withdrawals)
          ? parsed.withdrawals
          : [],

      transactions:
        Array.isArray(parsed.transactions)
          ? parsed.transactions
          : [],

      auditLogs:
        Array.isArray(parsed.auditLogs)
          ? parsed.auditLogs
          : []
    };
  } catch (error) {
    console.error(
      '❌ Failed to read data.json:',
      error.message
    );

    return emptyData();
  }
}

function writeData(data) {
  const temp = `${DATA_FILE}.tmp`;

  fs.writeFileSync(
    temp,
    JSON.stringify(data, null, 2),
    'utf8'
  );

  fs.renameSync(temp, DATA_FILE);
}

/* =========================================================
   APP / SECURITY / CORS
========================================================= */
app.set('trust proxy', 1);
app.disable('x-powered-by');

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: [
          "'self'"
        ],

        scriptSrc: [
          "'self'",
          "'unsafe-inline'",
          'https://cdnjs.cloudflare.com'
        ],

        styleSrc: [
          "'self'",
          "'unsafe-inline'",
          'https://fonts.googleapis.com',
          'https://cdnjs.cloudflare.com'
        ],

        fontSrc: [
          "'self'",
          'https://fonts.gstatic.com',
          'https://cdnjs.cloudflare.com',
          'data:'
        ],

        imgSrc: [
          "'self'",
          'data:',
          'https:'
        ],

        connectSrc: [
          "'self'",
          'https://back-production-766a.up.railway.app',
          'https://oceaniclending.name.ng',
          'https://www.oceaniclending.name.ng'
        ]
      }
    },

    crossOriginEmbedderPolicy: false
  })
);

const allowedOrigins = [
  'https://oceaniclending.name.ng',
  'https://www.oceaniclending.name.ng',
  'https://back-production-766a.up.railway.app',

  'http://localhost:3000',
  'http://localhost:5500',

  'http://127.0.0.1:3000',
  'http://127.0.0.1:5500'
];

app.use(
  cors({
    origin(origin, callback) {
      if (
        !origin ||
        allowedOrigins.includes(origin)
      ) {
        return callback(null, true);
      }

      console.warn(
        '❌ Blocked CORS origin:',
        origin
      );

      return callback(
        new Error(
          'Origin not allowed by CORS'
        )
      );
    },

    credentials: true,

    methods: [
      'GET',
      'POST',
      'PUT',
      'PATCH',
      'DELETE',
      'OPTIONS'
    ],

    allowedHeaders: [
      'Content-Type',
      'Authorization'
    ]
  })
);

app.use(
  express.json({
    limit: '100kb'
  })
);

app.use(
  express.urlencoded({
    extended: false,
    limit: '100kb'
  })
);

/* =========================================================
   RATE LIMITS
========================================================= */
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,

  limit: 20,

  standardHeaders: true,

  legacyHeaders: false,

  handler: (_req, res) =>
    res.status(429).json({
      error:
        'Too many login attempts. Please try again later.'
    })
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,

  limit: 500,

  standardHeaders: true,

  legacyHeaders: false,

  handler: (_req, res) =>
    res.status(429).json({
      error:
        'Too many requests. Please try again later.'
    })
});

app.use(
  '/api',
  apiLimiter
);

/* =========================================================
   VALIDATION
========================================================= */

const currencyEnum = z.enum([
  'NGN',
  'USD',
  'GBP',
  'EUR',
  'GHS',
  'KES',
  'ZAR'
]);

const registerSchema = z.object({
  fullName:
    z
      .string()
      .trim()
      .min(2)
      .max(120),

  email:
    z
      .string()
      .trim()
      .email()
      .max(320),

  phone:
    z
      .string()
      .trim()
      .min(7)
      .max(40),

  password:
    z
      .string()
      .min(8)
      .max(128)
});

const loginSchema = z.object({
  email:
    z
      .string()
      .trim()
      .email(),

  password:
    z
      .string()
      .min(1)
      .max(128)
});

const loanSchema = z.object({
  applicantName:
    z
      .string()
      .trim()
      .min(2)
      .max(120),

  country:
    z
      .string()
      .trim()
      .min(2)
      .max(100),

  addressTitle:
    z
      .string()
      .trim()
      .min(3)
      .max(500),

  city:
    z
      .string()
      .trim()
      .min(2)
      .max(100),

  stateRegion:
    z
      .string()
      .trim()
      .min(2)
      .max(100),

  phone:
    z
      .string()
      .trim()
      .min(7)
      .max(40),

  email:
    z
      .string()
      .trim()
      .email(),

  monthlyIncome:
    z
      .coerce
      .number()
      .positive(),

  loanAmount:
    z
      .coerce
      .number()
      .positive(),

  currency:
    currencyEnum,

  loanPeriodYears:
    z
      .coerce
      .number()
      .int()
      .min(1)
      .max(10),

  purpose:
    z
      .string()
      .trim()
      .min(3)
      .max(1000)
});

const withdrawalSchema = z.object({
  amount:
    z
      .coerce
      .number()
      .positive(),

  destination:
    z
      .string()
      .trim()
      .min(5)
      .max(1000)
});

const adminUserSchema = z
  .object({
    fullName:
      z
        .string()
        .trim()
        .min(2)
        .max(120)
        .optional(),

    phone:
      z
        .string()
        .trim()
        .min(7)
        .max(40)
        .optional(),

    status:
      z
        .enum([
          'active',
          'inactive',
          'suspended'
        ])
        .optional()
  })
  .refine(
    value =>
      Object.keys(value).length > 0,
    {
      message:
        'At least one field is required'
    }
  );

const verificationSchema = z.object({
  status:
    z.enum([
      'pending',
      'verified',
      'rejected'
    ]),

  note:
    z
      .string()
      .trim()
      .max(500)
      .optional()
      .nullable()
});

const fundAdjustmentSchema = z.object({
  action:
    z.enum([
      'credit',
      'debit'
    ]),

  amount:
    z
      .coerce
      .number()
      .positive()
      .max(
        1_000_000_000_000
      ),

  currency:
    currencyEnum,

  description:
    z
      .string()
      .trim()
      .min(3)
      .max(300),

  reference:
    z
      .string()
      .trim()
      .max(120)
      .optional()
});

const loanAdminSchema = z.object({
  status:
    z.enum([
      'under_review',
      'approved',
      'rejected',
      'cancelled'
    ]),

  reviewerNote:
    z
      .string()
      .trim()
      .max(1000)
      .optional()
      .nullable()
});

const withdrawalAdminSchema = z.object({
  status:
    z.enum([
      'pending',
      'processing',
      'completed',
      'rejected',
      'cancelled'
    ]),

  reviewerNote:
    z
      .string()
      .trim()
      .max(1000)
      .optional()
      .nullable()
});

function parseBody(
  schema,
  body,
  res
) {
  const result =
    schema.safeParse(body);

  if (!result.success) {
    res.status(400).json({
      error:
        'Validation failed',

      details:
        result.error.flatten()
    });

    return null;
  }

  return result.data;
}

/* =========================================================
   HELPERS
========================================================= */

function generateId() {
  return (
    Date.now().toString(36) +
    Math.random()
      .toString(36)
      .slice(2, 8)
  );
}

function estimateLoan(
  amount,
  years,
  rate = 0.12
) {
  const interest =
    amount * rate * years;

  const total =
    amount + interest;

  return {
    interest,
    total,
    monthly:
      total /
      (years * 12)
  };
}

function safeUser(user) {
  return {
    id:
      user.id,

    fullName:
      user.fullName,

    email:
      user.email,

    phone:
      user.phone,

    balance:
      Number(
        user.balance || 0
      ),

    currency:
      user.currency || 'NGN',

    status:
      user.status || 'active',

    verificationStatus:
      user.verificationStatus ||
      'pending',

    verifiedAt:
      user.verifiedAt || null,

    createdAt:
      user.createdAt,

    updatedAt:
      user.updatedAt ||
      user.createdAt
  };
}

function adminUserView(user) {
  return {
    ...safeUser(user),

    verificationNote:
      user.verificationNote ||
      null
  };
}

function secureEqual(a, b) {
  const aa =
    Buffer.from(
      String(a)
    );

  const bb =
    Buffer.from(
      String(b)
    );

  if (
    aa.length !== bb.length
  ) {
    return false;
  }

  return crypto.timingSafeEqual(
    aa,
    bb
  );
}

function addAudit(
  data,
  action,
  details = {}
) {
  data.auditLogs.unshift({
    id:
      generateId(),

    action,

    details,

    createdAt:
      new Date().toISOString()
  });

  data.auditLogs =
    data.auditLogs.slice(
      0,
      1000
    );
}

function makeTransaction(
  data,
  {
    userId,
    type,
    amount,
    currency,
    status = 'completed',
    reference,
    description
  }
) {
  const transaction = {
    id:
      generateId(),

    userId,

    type,

    amount:
      Number(amount),

    currency,

    status,

    reference:
      reference ||
      `${type
        .toUpperCase()
        .slice(0, 4)}-${generateId()}`,

    description,

    createdAt:
      new Date().toISOString()
  };

  data.transactions.push(
    transaction
  );

  return transaction;
}

/* =========================================================
   USER AUTH MIDDLEWARE
========================================================= */

function auth(
  req,
  res,
  next
) {
  try {
    const header =
      req.headers.authorization;

    if (
      !header ||
      !header.startsWith(
        'Bearer '
      )
    ) {
      return res
        .status(401)
        .json({
          error:
            'Authentication required'
        });
    }

    const decoded =
      jwt.verify(
        header.substring(7),
        process.env.JWT_SECRET
      );

    const data =
      readData();

    const user =
      data.users.find(
        item =>
          item.id ===
          decoded.sub
      );

    if (!user) {
      return res
        .status(401)
        .json({
          error:
            'User account not found'
        });
    }

    if (
      user.status !==
      'active'
    ) {
      return res
        .status(403)
        .json({
          error:
            'Account unavailable'
        });
    }

    req.user = user;

    next();
  } catch (_error) {
    return res
      .status(401)
      .json({
        error:
          'Invalid or expired token'
      });
  }
}

/* =========================================================
   ADMIN AUTH MIDDLEWARE
========================================================= */

function adminAuth(
  req,
  res,
  next
) {
  try {
    const header =
      req.headers.authorization;

    if (
      !header ||
      !header.startsWith(
        'Bearer '
      )
    ) {
      return res
        .status(401)
        .json({
          error:
            'Admin authentication required'
        });
    }

    const decoded =
      jwt.verify(
        header.substring(7),
        process.env.JWT_SECRET
      );

    if (
      decoded.role !==
        'admin' ||
      decoded.type !==
        'admin'
    ) {
      return res
        .status(403)
        .json({
          error:
            'Admin access required'
        });
    }

    req.admin = decoded;

    next();
  } catch (_error) {
    return res
      .status(401)
      .json({
        error:
          'Invalid or expired admin token'
      });
  }
}

/* =========================================================
   HEALTH
========================================================= */

app.get(
  '/api/health',
  (_req, res) => {
    res.json({
      ok: true,

      service:
        'oceanic-lending-api',

      environment:
        process.env.NODE_ENV ||
        'development',

      timestamp:
        new Date().toISOString()
    });
  }
);

/* =========================================================
   ADMIN AUTH
========================================================= */

app.post(
  '/api/admin/login',
  authLimiter,
  (req, res) => {
    const username =
      typeof req.body
        .username ===
      'string'
        ? req.body.username.trim()
        : '';

    const password =
      typeof req.body
        .password ===
      'string'
        ? req.body.password
        : '';

    if (
      !username ||
      !password
    ) {
      return res
        .status(400)
        .json({
          error:
            'Username and password are required'
        });
    }

    if (
      !secureEqual(
        username,
        process.env.ADMIN_USERNAME
      ) ||
      !secureEqual(
        password,
        process.env.ADMIN_PASSWORD
      )
    ) {
      return res
        .status(401)
        .json({
          error:
            'Invalid admin credentials'
        });
    }

    const token =
      jwt.sign(
        {
          role: 'admin',
          type: 'admin'
        },

        process.env.JWT_SECRET,

        {
          expiresIn:
            '24h'
        }
      );

    res.json({
      token,
      role: 'admin'
    });
  }
);

/* =========================================================
   ADMIN DASHBOARD
========================================================= */

app.get(
  '/api/admin/dashboard',
  adminAuth,
  (_req, res) => {
    const data =
      readData();

    res.json({
      users:
        data.users.map(
          adminUserView
        ),

      loans:
        [...data.loans].sort(
          (a, b) =>
            new Date(
              b.createdAt
            ) -
            new Date(
              a.createdAt
            )
        ),

      withdrawals:
        [...data.withdrawals].sort(
          (a, b) =>
            new Date(
              b.createdAt
            ) -
            new Date(
              a.createdAt
            )
        ),

      transactions:
        [...data.transactions].sort(
          (a, b) =>
            new Date(
              b.createdAt
            ) -
            new Date(
              a.createdAt
            )
        ),

      auditLogs:
        data.auditLogs
    });
  }
);

/* =========================================================
   ADMIN USER CONTROL
========================================================= */

app.patch(
  '/api/admin/users/:id',
  adminAuth,
  (req, res) => {
    const form =
      parseBody(
        adminUserSchema,
        req.body,
        res
      );

    if (!form) {
      return;
    }

    const data =
      readData();

    const user =
      data.users.find(
        item =>
          item.id ===
          req.params.id
      );

    if (!user) {
      return res
        .status(404)
        .json({
          error:
            'User not found'
        });
    }

    const before = {
      fullName:
        user.fullName,

      phone:
        user.phone,

      status:
        user.status
    };

    if (
      form.fullName !==
      undefined
    ) {
      user.fullName =
        form.fullName;
    }

    if (
      form.phone !==
      undefined
    ) {
      user.phone =
        form.phone;
    }

    if (
      form.status !==
      undefined
    ) {
      user.status =
        form.status;
    }

    user.updatedAt =
      new Date().toISOString();

    addAudit(
      data,
      'user_updated',
      {
        userId:
          user.id,

        before,

        after: {
          fullName:
            user.fullName,

          phone:
            user.phone,

          status:
            user.status
        }
      }
    );

    writeData(data);

    res.json({
      user:
        safeUser(user)
    });
  }
);

/* =========================================================
   ADMIN VERIFY / REJECT USER
========================================================= */

app.patch(
  '/api/admin/users/:id/verification',
  adminAuth,
  (req, res) => {
    const form =
      parseBody(
        verificationSchema,
        req.body,
        res
      );

    if (!form) {
      return;
    }

    const data =
      readData();

    const user =
      data.users.find(
        item =>
          item.id ===
          req.params.id
      );

    if (!user) {
      return res
        .status(404)
        .json({
          error:
            'User not found'
        });
    }

    const previous =
      user.verificationStatus ||
      'pending';

    user.verificationStatus =
      form.status;

    user.verificationNote =
      form.note || null;

    user.verifiedAt =
      form.status ===
      'verified'
        ? new Date()
            .toISOString()
        : null;

    user.updatedAt =
      new Date()
        .toISOString();

    addAudit(
      data,
      'verification_updated',
      {
        userId:
          user.id,

        previousStatus:
          previous,

        status:
          form.status,

        note:
          user.verificationNote
      }
    );

    writeData(data);

    res.json({
      user:
        safeUser(user)
    });
  }
);

/* =========================================================
   ADMIN ADD / DEDUCT FUNDS
========================================================= */

app.post(
  '/api/admin/users/:id/funds',
  adminAuth,
  (req, res) => {
    const form =
      parseBody(
        fundAdjustmentSchema,
        req.body,
        res
      );

    if (!form) {
      return;
    }

    const data =
      readData();

    const user =
      data.users.find(
        item =>
          item.id ===
          req.params.id
      );

    if (!user) {
      return res
        .status(404)
        .json({
          error:
            'User not found'
        });
    }

    if (
      form.currency !==
      (
        user.currency ||
        'NGN'
      )
    ) {
      return res
        .status(409)
        .json({
          error:
            `Currency mismatch. This wallet is ${user.currency || 'NGN'}; fund adjustments must use the same currency.`
        });
    }

    const current =
      Number(
        user.balance || 0
      );

    const amount =
      Number(
        form.amount
      );

    if (
      form.action ===
        'debit' &&
      amount > current
    ) {
      return res
        .status(400)
        .json({
          error:
            'Debit amount exceeds available wallet balance'
        });
    }

    user.balance =
      form.action ===
      'credit'
        ? current + amount
        : current - amount;

    user.updatedAt =
      new Date()
        .toISOString();

    const transaction =
      makeTransaction(
        data,
        {
          userId:
            user.id,

          type:
            form.action ===
            'credit'
              ? 'admin_credit'
              : 'admin_debit',

          amount,

          currency:
            form.currency,

          status:
            'completed',

          reference:
            form.reference ||
            `ADM-${generateId()}`,

          description:
            form.description
        }
      );

    addAudit(
      data,
      'fund_adjustment',
      {
        userId:
          user.id,

        action:
          form.action,

        amount,

        currency:
          form.currency,

        transactionId:
          transaction.id,

        description:
          form.description
      }
    );

    writeData(data);

    res.json({
      user:
        safeUser(user),

      transaction
    });
  }
);

/* =========================================================
   ADMIN LOAN CONTROL
========================================================= */

app.patch(
  '/api/admin/loans/:id',
  adminAuth,
  (req, res) => {
    const form =
      parseBody(
        loanAdminSchema,
        req.body,
        res
      );

    if (!form) {
      return;
    }

    const data =
      readData();

    const loan =
      data.loans.find(
        item =>
          item.id ===
          req.params.id
      );

    if (!loan) {
      return res
        .status(404)
        .json({
          error:
            'Loan not found'
        });
    }

    const previousStatus =
      loan.status;

    loan.status =
      form.status;

    loan.reviewerNote =
      form.reviewerNote ||
      null;

    loan.updatedAt =
      new Date()
        .toISOString();

    loan.reviewedAt =
      new Date()
        .toISOString();

    /*
      Only disburse the loan one time.
    */
    if (
      form.status ===
        'approved' &&
      !loan.disbursedAt
    ) {
      const user =
        data.users.find(
          item =>
            item.id ===
            loan.userId
        );

      if (!user) {
        return res
          .status(404)
          .json({
            error:
              'Loan owner not found'
          });
      }

      const walletCurrency =
        user.currency ||
        'NGN';

      if (
        loan.currency !==
        walletCurrency
      ) {
        return res
          .status(409)
          .json({
            error:
              `Cannot disburse ${loan.currency} into a ${walletCurrency} wallet. The application must use the wallet currency.`
          });
      }

      user.balance =
        Number(
          user.balance || 0
        ) +
        Number(
          loan.loanAmount
        );

      user.updatedAt =
        new Date()
          .toISOString();

      const transaction =
        makeTransaction(
          data,
          {
            userId:
              user.id,

            type:
              'loan_disbursement',

            amount:
              Number(
                loan.loanAmount
              ),

            currency:
              walletCurrency,

            status:
              'completed',

            reference:
              `LN-${generateId()}`,

            description:
              'Loan approved and disbursed'
          }
        );

      loan.disbursedAt =
        new Date()
          .toISOString();

      loan.disbursementTransactionId =
        transaction.id;
    }

    addAudit(
      data,
      'loan_status_updated',
      {
        loanId:
          loan.id,

        userId:
          loan.userId,

        previousStatus,

        status:
          loan.status,

        reviewerNote:
          loan.reviewerNote
      }
    );

    writeData(data);

    res.json({
      loan
    });
  }
);

/* =========================================================
   ADMIN WITHDRAWAL CONTROL
========================================================= */

app.patch(
  '/api/admin/withdrawals/:id',
  adminAuth,
  (req, res) => {
    const form =
      parseBody(
        withdrawalAdminSchema,
        req.body,
        res
      );

    if (!form) {
      return;
    }

    const data =
      readData();

    const withdrawal =
      data.withdrawals.find(
        item =>
          item.id ===
          req.params.id
      );

    if (!withdrawal) {
      return res
        .status(404)
        .json({
          error:
            'Withdrawal not found'
        });
    }

    const previousStatus =
      withdrawal.status;

    withdrawal.status =
      form.status;

    withdrawal.reviewerNote =
      form.reviewerNote ||
      null;

    withdrawal.updatedAt =
      new Date()
        .toISOString();

    withdrawal.reviewedAt =
      new Date()
        .toISOString();

    /*
      Update original withdrawal transaction.
    */
    const transaction =
      data.transactions.find(
        item =>
          item.type ===
            'withdrawal' &&
          item.reference ===
            withdrawal.reference &&
          item.userId ===
            withdrawal.userId
      );

    if (transaction) {
      transaction.status =
        form.status;
    }

    const isRefundStatus =
      form.status ===
        'rejected' ||
      form.status ===
        'cancelled';

    const wasRefundStatus =
      previousStatus ===
        'rejected' ||
      previousStatus ===
        'cancelled';

    /*
      Refund only once.
    */
    if (
      isRefundStatus &&
      !wasRefundStatus &&
      !withdrawal.refundedAt
    ) {
      const user =
        data.users.find(
          item =>
            item.id ===
            withdrawal.userId
        );

      if (user) {
        user.balance =
          Number(
            user.balance || 0
          ) +
          Number(
            withdrawal.amount
          );

        user.updatedAt =
          new Date()
            .toISOString();

        makeTransaction(
          data,
          {
            userId:
              user.id,

            type:
              'withdrawal_reversal',

            amount:
              Number(
                withdrawal.amount
              ),

            currency:
              withdrawal.currency ||
              user.currency ||
              'NGN',

            status:
              'completed',

            reference:
              `RV-${generateId()}`,

            description:
              `Withdrawal reversed: ${withdrawal.reference}`
          }
        );

        withdrawal.refundedAt =
          new Date()
            .toISOString();
      }
    }

    /*
      If a previously rejected/cancelled
      withdrawal is reopened, reserve the
      money again.
    */
    if (
      !isRefundStatus &&
      wasRefundStatus &&
      withdrawal.refundedAt
    ) {
      const user =
        data.users.find(
          item =>
            item.id ===
            withdrawal.userId
        );

      if (!user) {
        return res
          .status(404)
          .json({
            error:
              'Withdrawal owner not found'
          });
      }

      const amount =
        Number(
          withdrawal.amount
        );

      if (
        Number(
          user.balance || 0
        ) < amount
      ) {
        return res
          .status(409)
          .json({
            error:
              'Cannot reopen withdrawal because the user no longer has enough available balance'
          });
      }

      user.balance =
        Number(
          user.balance || 0
        ) -
        amount;

      user.updatedAt =
        new Date()
          .toISOString();

      makeTransaction(
        data,
        {
          userId:
            user.id,

          type:
            'withdrawal_reserve',

          amount,

          currency:
            withdrawal.currency ||
            user.currency ||
            'NGN',

          status:
            'completed',

          reference:
            `RSV-${generateId()}`,

          description:
            `Funds reserved again for withdrawal: ${withdrawal.reference}`
        }
      );

      withdrawal.refundedAt =
        null;
    }

    addAudit(
      data,
      'withdrawal_status_updated',
      {
        withdrawalId:
          withdrawal.id,

        userId:
          withdrawal.userId,

        previousStatus,

        status:
          withdrawal.status,

        reviewerNote:
          withdrawal.reviewerNote
      }
    );

    writeData(data);

    res.json({
      withdrawal
    });
  }
);

/* =========================================================
   USER REGISTER
========================================================= */

app.post(
  '/api/auth/register',
  authLimiter,
  async (
    req,
    res,
    next
  ) => {
    try {
      const form =
        parseBody(
          registerSchema,
          req.body,
          res
        );

      if (!form) {
        return;
      }

      const data =
        readData();

      const email =
        form.email
          .trim()
          .toLowerCase();

      if (
        data.users.some(
          item =>
            String(
              item.email
            ).toLowerCase() ===
            email
        )
      ) {
        return res
          .status(409)
          .json({
            error:
              'An account with this email already exists'
          });
      }

      const user = {
        id:
          generateId(),

        fullName:
          form.fullName.trim(),

        email,

        phone:
          form.phone.trim(),

        password:
          await bcrypt.hash(
            form.password,
            12
          ),

        balance:
          0,

        currency:
          'NGN',

        status:
          'active',

        verificationStatus:
          'pending',

        verificationNote:
          null,

        verifiedAt:
          null,

        createdAt:
          new Date()
            .toISOString(),

        updatedAt:
          new Date()
            .toISOString()
      };

      data.users.push(
        user
      );

      writeData(data);

      const token =
        jwt.sign(
          {
            sub:
              user.id,

            email:
              user.email
          },

          process.env.JWT_SECRET,

          {
            expiresIn:
              '7d'
          }
        );

      res
        .status(201)
        .json({
          user:
            safeUser(user),

          token
        });
    } catch (error) {
      next(error);
    }
  }
);

/* =========================================================
   USER LOGIN
========================================================= */

app.post(
  '/api/auth/login',
  authLimiter,
  async (
    req,
    res,
    next
  ) => {
    try {
      const form =
        parseBody(
          loginSchema,
          req.body,
          res
        );

      if (!form) {
        return;
      }

      const data =
        readData();

      const email =
        form.email
          .trim()
          .toLowerCase();

      const user =
        data.users.find(
          item =>
            String(
              item.email
            ).toLowerCase() ===
            email
        );

      if (
        !user ||
        !(
          await bcrypt.compare(
            form.password,
            user.password
          )
        )
      ) {
        return res
          .status(401)
          .json({
            error:
              'Invalid credentials'
          });
      }

      if (
        user.status !==
        'active'
      ) {
        return res
          .status(403)
          .json({
            error:
              'Account unavailable'
          });
      }

      const token =
        jwt.sign(
          {
            sub:
              user.id,

            email:
              user.email
          },

          process.env.JWT_SECRET,

          {
            expiresIn:
              '7d'
          }
        );

      res.json({
        user:
          safeUser(user),

        token
      });
    } catch (error) {
      next(error);
    }
  }
);

/* =========================================================
   USER PROFILE
========================================================= */

app.get(
  '/api/me',
  auth,
  (
    req,
    res
  ) => {
    res.json({
      user:
        safeUser(
          req.user
        )
    });
  }
);

/* =========================================================
   USER WALLET
========================================================= */

app.get(
  '/api/wallet',
  auth,
  (
    req,
    res
  ) => {
    const data =
      readData();

    const user =
      data.users.find(
        item =>
          item.id ===
          req.user.id
      );

    if (!user) {
      return res
        .status(404)
        .json({
          error:
            'User not found'
        });
    }

    const transactions =
      data.transactions
        .filter(
          item =>
            item.userId ===
            req.user.id
        )
        .sort(
          (a, b) =>
            new Date(
              b.createdAt
            ) -
            new Date(
              a.createdAt
            )
        );

    res.json({
      wallet: {
        balance:
          Number(
            user.balance || 0
          ),

        currency:
          user.currency ||
          'NGN'
      },

      transactions:
        transactions.slice(
          0,
          100
        )
    });
  }
);

/* =========================================================
   GET USER LOANS
========================================================= */

app.get(
  '/api/loans',
  auth,
  (
    req,
    res
  ) => {
    const data =
      readData();

    const loans =
      data.loans
        .filter(
          item =>
            item.userId ===
            req.user.id
        )
        .sort(
          (a, b) =>
            new Date(
              b.createdAt
            ) -
            new Date(
              a.createdAt
            )
        );

    res.json({
      loans
    });
  }
);

/* =========================================================
   CREATE LOAN
========================================================= */

app.post(
  '/api/loans',
  auth,
  (
    req,
    res,
    next
  ) => {
    try {
      const form =
        parseBody(
          loanSchema,
          req.body,
          res
        );

      if (!form) {
        return;
      }

      const data =
        readData();

      const user =
        data.users.find(
          item =>
            item.id ===
            req.user.id
        );

      if (!user) {
        return res
          .status(404)
          .json({
            error:
              'User not found'
          });
      }

      /*
        Do not allow a loan currency
        that is different from the
        wallet currency.
      */
      if (
        form.currency !==
        (
          user.currency ||
          'NGN'
        )
      ) {
        return res
          .status(400)
          .json({
            error:
              `Your wallet is ${user.currency || 'NGN'}. Please submit the loan request in the same currency.`
          });
      }

      const estimate =
        estimateLoan(
          form.loanAmount,
          form.loanPeriodYears
        );

      const now =
        new Date()
          .toISOString();

      const loan = {
        id:
          generateId(),

        userId:
          req.user.id,

        applicantName:
          form.applicantName,

        country:
          form.country,

        addressTitle:
          form.addressTitle,

        city:
          form.city,

        stateRegion:
          form.stateRegion,

        phone:
          form.phone,

        email:
          form.email,

        monthlyIncome:
          form.monthlyIncome,

        loanAmount:
          form.loanAmount,

        currency:
          form.currency,

        loanPeriodYears:
          form.loanPeriodYears,

        purpose:
          form.purpose,

        status:
          'under_review',

        reviewerNote:
          null,

        estimatedInterest:
          estimate.interest,

        estimatedTotalRepayment:
          estimate.total,

        estimatedMonthlyPayment:
          estimate.monthly,

        createdAt:
          now,

        updatedAt:
          now
      };

      data.loans.push(
        loan
      );

      writeData(data);

      res
        .status(201)
        .json({
          loan
        });
    } catch (error) {
      next(error);
    }
  }
);

/* =========================================================
   GET USER WITHDRAWALS
========================================================= */

app.get(
  '/api/withdrawals',
  auth,
  (
    req,
    res
  ) => {
    const data =
      readData();

    const withdrawals =
      data.withdrawals
        .filter(
          item =>
            item.userId ===
            req.user.id
        )
        .sort(
          (a, b) =>
            new Date(
              b.createdAt
            ) -
            new Date(
              a.createdAt
            )
        );

    res.json({
      withdrawals
    });
  }
);

/* =========================================================
   CREATE WITHDRAWAL
========================================================= */

app.post(
  '/api/withdrawals',
  auth,
  (
    req,
    res,
    next
  ) => {
    try {
      const form =
        parseBody(
          withdrawalSchema,
          req.body,
          res
        );

      if (!form) {
        return;
      }

      const data =
        readData();

      const user =
        data.users.find(
          item =>
            item.id ===
            req.user.id
        );

      if (!user) {
        return res
          .status(404)
          .json({
            error:
              'User not found'
          });
      }

      const balance =
        Number(
          user.balance || 0
        );

      const amount =
        Number(
          form.amount
        );

      if (
        amount >
        balance
      ) {
        return res
          .status(400)
          .json({
            error:
              'Insufficient balance'
          });
      }

      /*
        Reserve the withdrawal money
        immediately so the user cannot
        withdraw the same balance twice.
      */
      user.balance =
        balance - amount;

      user.updatedAt =
        new Date()
          .toISOString();

      const reference =
        `WD-${generateId()}`;

      const now =
        new Date()
          .toISOString();

      const withdrawal = {
        id:
          generateId(),

        userId:
          req.user.id,

        amount,

        currency:
          user.currency ||
          'NGN',

        destination:
          form.destination,

        reference,

        status:
          'pending',

        reviewerNote:
          null,

        refundedAt:
          null,

        createdAt:
          now,

        updatedAt:
          now
      };

      data.withdrawals.push(
        withdrawal
      );

      makeTransaction(
        data,
        {
          userId:
            req.user.id,

          type:
            'withdrawal',

          amount,

          currency:
            user.currency ||
            'NGN',

          status:
            'pending',

          reference,

          description:
            'Withdrawal request submitted'
        }
      );

      writeData(data);

      res
        .status(201)
        .json({
          reference,

          status:
            'pending'
        });
    } catch (error) {
      next(error);
    }
  }
);

/* =========================================================
   API 404
========================================================= */

app.use(
  '/api',
  (
    req,
    res
  ) =>
    res
      .status(404)
      .json({
        error:
          'API endpoint not found',

        method:
          req.method,

        path:
          req.originalUrl
      })
);

/* =========================================================
   SERVE FRONTEND
========================================================= */

app.use(
  express.static(
    __dirname
  )
);

app.get(
  '/',
  (
    _req,
    res
  ) =>
    res.sendFile(
      path.join(
        __dirname,
        'index.html'
      )
    )
);

app.get(
  '/admin',
  (
    _req,
    res
  ) =>
    res.sendFile(
      path.join(
        __dirname,
        'admin.html'
      )
    )
);

/* =========================================================
   PAGE 404
========================================================= */

app.use(
  (
    req,
    res
  ) => {
    if (
      req.originalUrl.startsWith(
        '/api'
      )
    ) {
      return res
        .status(404)
        .json({
          error:
            'API endpoint not found'
        });
    }

    res
      .status(404)
      .send(
        'Page not found'
      );
  }
);

/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
  (
    err,
    req,
    res,
    next
  ) => {
    console.error(
      '❌ Server error:',
      err
    );

    if (
      res.headersSent
    ) {
      return next(err);
    }

    if (
      err instanceof SyntaxError &&
      err.status === 400 &&
      'body' in err
    ) {
      return res
        .status(400)
        .json({
          error:
            'Invalid JSON request body'
        });
    }

    if (
      req.originalUrl.startsWith(
        '/api'
      )
    ) {
      return res
        .status(
          err.status ||
          500
        )
        .json({
          error:
            process.env.NODE_ENV ===
            'production'
              ? 'Internal server error'
              : (
                  err.message ||
                  'Internal server error'
                )
        });
    }

    res
      .status(
        err.status ||
        500
      )
      .send(
        'Internal server error'
      );
  }
);

/* =========================================================
   START SERVER
========================================================= */

app.listen(
  PORT,
  '0.0.0.0',
  () => {
    console.log('');
    console.log(
      '✅ Oceanic Lending API started'
    );
    console.log(
      `✅ Port: ${PORT}`
    );
    console.log(
      '✅ Health: /api/health'
    );
    console.log(
      '✅ Admin: /admin'
    );
    console.log('');
  }
);
