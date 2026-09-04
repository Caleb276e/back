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

const app = express();

const PORT = process.env.PORT || 8080;
const DATA_FILE = path.join(__dirname, 'data.json');

/* =========================================================
   REQUIRED ENVIRONMENT VARIABLES
========================================================= */

if (!process.env.JWT_SECRET) {
    console.error('❌ Missing JWT_SECRET environment variable');
    process.exit(1);
}

if (!process.env.ADMIN_USERNAME) {
    console.error('❌ Missing ADMIN_USERNAME environment variable');
    process.exit(1);
}

if (!process.env.ADMIN_PASSWORD) {
    console.error('❌ Missing ADMIN_PASSWORD environment variable');
    process.exit(1);
}

/* =========================================================
   DATA FILE
========================================================= */

function emptyData() {
    return {
        users: [],
        loans: [],
        withdrawals: [],
        transactions: []
    };
}

if (!fs.existsSync(DATA_FILE)) {
    fs.writeFileSync(
        DATA_FILE,
        JSON.stringify(emptyData(), null, 2),
        'utf8'
    );
}

function readData() {
    try {
        const raw = fs.readFileSync(DATA_FILE, 'utf8');

        if (!raw.trim()) {
            return emptyData();
        }

        const data = JSON.parse(raw);

        return {
            users: Array.isArray(data.users) ? data.users : [],
            loans: Array.isArray(data.loans) ? data.loans : [],
            withdrawals: Array.isArray(data.withdrawals)
                ? data.withdrawals
                : [],
            transactions: Array.isArray(data.transactions)
                ? data.transactions
                : []
        };
    } catch (error) {
        console.error('❌ Failed to read data.json:', error.message);
        return emptyData();
    }
}

function writeData(data) {
    try {
        fs.writeFileSync(
            DATA_FILE,
            JSON.stringify(data, null, 2),
            'utf8'
        );
    } catch (error) {
        console.error('❌ Failed to write data.json:', error);
        throw error;
    }
}

/* =========================================================
   BASIC APP CONFIG
========================================================= */

app.set('trust proxy', 1);
app.disable('x-powered-by');

/* =========================================================
   SECURITY
========================================================= */

app.use(
    helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],

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

/* =========================================================
   CORS
========================================================= */

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
            /*
             Allow requests such as curl/Postman/server-to-server
             where Origin may not be present.
            */
            if (!origin) {
                return callback(null, true);
            }

            if (allowedOrigins.includes(origin)) {
                return callback(null, true);
            }

            console.warn('❌ Blocked CORS origin:', origin);

            return callback(
                new Error('Origin not allowed by CORS')
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

/* =========================================================
   BODY PARSING
========================================================= */

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
   RATE LIMITING
========================================================= */

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 20,
    standardHeaders: true,
    legacyHeaders: false,

    handler: (req, res) => {
        return res.status(429).json({
            error: 'Too many login attempts. Please try again later.'
        });
    }
});

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 300,
    standardHeaders: true,
    legacyHeaders: false,

    handler: (req, res) => {
        return res.status(429).json({
            error: 'Too many requests. Please try again later.'
        });
    }
});

app.use('/api', apiLimiter);

/* =========================================================
   VALIDATION
========================================================= */

const registerSchema = z.object({
    fullName: z
        .string()
        .trim()
        .min(2)
        .max(120),

    email: z
        .string()
        .trim()
        .email()
        .max(320),

    phone: z
        .string()
        .trim()
        .min(7)
        .max(40),

    password: z
        .string()
        .min(8)
        .max(128)
});

const loginSchema = z.object({
    email: z
        .string()
        .trim()
        .email(),

    password: z
        .string()
        .min(1)
        .max(128)
});

const loanSchema = z.object({
    applicantName: z
        .string()
        .trim()
        .min(2)
        .max(120),

    country: z
        .string()
        .trim()
        .min(2)
        .max(100),

    addressTitle: z
        .string()
        .trim()
        .min(3)
        .max(500),

    city: z
        .string()
        .trim()
        .min(2)
        .max(100),

    stateRegion: z
        .string()
        .trim()
        .min(2)
        .max(100),

    phone: z
        .string()
        .trim()
        .min(7)
        .max(40),

    email: z
        .string()
        .trim()
        .email(),

    monthlyIncome: z
        .coerce
        .number()
        .positive(),

    loanAmount: z
        .coerce
        .number()
        .positive(),

    currency: z.enum([
        'NGN',
        'USD',
        'GBP',
        'EUR',
        'GHS',
        'KES',
        'ZAR'
    ]),

    loanPeriodYears: z
        .coerce
        .number()
        .int()
        .min(1)
        .max(10),

    purpose: z
        .string()
        .trim()
        .min(3)
        .max(1000)
});

const withdrawalSchema = z.object({
    amount: z
        .coerce
        .number()
        .positive(),

    destination: z
        .string()
        .trim()
        .min(5)
        .max(1000)
});

function parseBody(schema, body, res) {
    const result = schema.safeParse(body);

    if (!result.success) {
        res.status(400).json({
            error: 'Validation failed',
            details: result.error.flatten()
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
        Math.random().toString(36).slice(2, 8)
    );
}

function estimateLoan(amount, years, rate = 0.12) {
    const interest = amount * rate * years;
    const total = amount + interest;

    return {
        interest,
        total,
        monthly: total / (years * 12)
    };
}

function safeUser(user) {
    return {
        id: user.id,
        fullName: user.fullName,
        email: user.email,
        phone: user.phone,
        balance: user.balance || 0,
        currency: user.currency || 'NGN',
        status: user.status,
        createdAt: user.createdAt
    };
}

/* =========================================================
   USER AUTH MIDDLEWARE
========================================================= */

function auth(req, res, next) {
    try {
        const authHeader = req.headers.authorization;

        if (
            !authHeader ||
            !authHeader.startsWith('Bearer ')
        ) {
            return res.status(401).json({
                error: 'Authentication required'
            });
        }

        const token = authHeader.substring(7);

        const decoded = jwt.verify(
            token,
            process.env.JWT_SECRET
        );

        const data = readData();

        const user = data.users.find(
            (item) => item.id === decoded.sub
        );

        if (!user) {
            return res.status(401).json({
                error: 'User account not found'
            });
        }

        if (user.status !== 'active') {
            return res.status(403).json({
                error: 'Account unavailable'
            });
        }

        req.user = user;

        next();
    } catch (error) {
        return res.status(401).json({
            error: 'Invalid or expired token'
        });
    }
}

/* =========================================================
   ADMIN AUTH MIDDLEWARE
========================================================= */

function adminAuth(req, res, next) {
    try {
        const authHeader = req.headers.authorization;

        if (
            !authHeader ||
            !authHeader.startsWith('Bearer ')
        ) {
            return res.status(401).json({
                error: 'Admin authentication required'
            });
        }

        const token = authHeader.substring(7);

        const decoded = jwt.verify(
            token,
            process.env.JWT_SECRET
        );

        if (
            decoded.role !== 'admin' ||
            decoded.type !== 'admin'
        ) {
            return res.status(403).json({
                error: 'Admin access required'
            });
        }

        req.admin = decoded;

        next();
    } catch (error) {
        return res.status(401).json({
            error: 'Invalid or expired admin token'
        });
    }
}

/* =========================================================
   HEALTH CHECK
========================================================= */

app.get('/api/health', (req, res) => {
    return res.status(200).json({
        ok: true,
        service: 'oceanic-lending-api',
        environment:
            process.env.NODE_ENV || 'development',
        timestamp: new Date().toISOString()
    });
});

/* =========================================================
   ADMIN LOGIN
========================================================= */

app.post(
    '/api/admin/login',
    authLimiter,
    (req, res) => {
        const username =
            typeof req.body.username === 'string'
                ? req.body.username.trim()
                : '';

        const password =
            typeof req.body.password === 'string'
                ? req.body.password
                : '';

        if (!username || !password) {
            return res.status(400).json({
                error: 'Username and password are required'
            });
        }

        if (
            username !== process.env.ADMIN_USERNAME ||
            password !== process.env.ADMIN_PASSWORD
        ) {
            return res.status(401).json({
                error: 'Invalid admin credentials'
            });
        }

        const token = jwt.sign(
            {
                role: 'admin',
                type: 'admin'
            },
            process.env.JWT_SECRET,
            {
                expiresIn: '24h'
            }
        );

        return res.json({
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
    (req, res) => {
        const data = readData();

        return res.json({
            users: data.users.map(safeUser),
            loans: data.loans,
            withdrawals: data.withdrawals,
            transactions: data.transactions
        });
    }
);

/* =========================================================
   ADMIN UPDATE LOAN
========================================================= */

app.patch(
    '/api/admin/loans/:id',
    adminAuth,
    (req, res) => {
        const {
            status,
            reviewerNote
        } = req.body;

        const allowedStatuses = [
            'under_review',
            'approved',
            'rejected',
            'cancelled'
        ];

        if (!allowedStatuses.includes(status)) {
            return res.status(400).json({
                error: 'Invalid loan status'
            });
        }

        const data = readData();

        const loan = data.loans.find(
            (item) => item.id === req.params.id
        );

        if (!loan) {
            return res.status(404).json({
                error: 'Loan not found'
            });
        }

        const previousStatus = loan.status;

        loan.status = status;
        loan.reviewerNote =
            reviewerNote || null;
        loan.updatedAt =
            new Date().toISOString();

        /*
         Only credit the account once when the
         loan first changes to approved.
        */
        if (
            status === 'approved' &&
            previousStatus !== 'approved'
        ) {
            const user = data.users.find(
                (item) =>
                    item.id === loan.userId
            );

            if (!user) {
                return res.status(404).json({
                    error: 'Loan owner not found'
                });
            }

            user.balance =
                Number(user.balance || 0) +
                Number(loan.loanAmount);

            data.transactions.push({
                id: generateId(),
                userId: user.id,
                type: 'loan_disbursement',
                amount: Number(
                    loan.loanAmount
                ),
                currency:
                    loan.currency ||
                    user.currency ||
                    'NGN',
                status: 'completed',
                reference:
                    `LN-${generateId()}`,
                description:
                    'Loan approved and disbursed',
                createdAt:
                    new Date().toISOString()
            });
        }

        writeData(data);

        return res.json({
            loan
        });
    }
);

/* =========================================================
   ADMIN UPDATE WITHDRAWAL
========================================================= */

app.patch(
    '/api/admin/withdrawals/:id',
    adminAuth,
    (req, res) => {
        const {
            status,
            reviewerNote
        } = req.body;

        const allowedStatuses = [
            'pending',
            'processing',
            'completed',
            'rejected',
            'cancelled'
        ];

        if (!allowedStatuses.includes(status)) {
            return res.status(400).json({
                error: 'Invalid withdrawal status'
            });
        }

        const data = readData();

        const withdrawal =
            data.withdrawals.find(
                (item) =>
                    item.id === req.params.id
            );

        if (!withdrawal) {
            return res.status(404).json({
                error: 'Withdrawal not found'
            });
        }

        const previousStatus =
            withdrawal.status;

        withdrawal.status = status;
        withdrawal.reviewerNote =
            reviewerNote || null;
        withdrawal.updatedAt =
            new Date().toISOString();

        /*
         Update original withdrawal transaction.
        */
        const transaction =
            data.transactions.find(
                (item) =>
                    item.type === 'withdrawal' &&
                    item.reference ===
                        withdrawal.reference &&
                    item.userId ===
                        withdrawal.userId
            );

        if (transaction) {
            transaction.status = status;
        }

        /*
         Only refund once.
        */
        const isRefundStatus =
            status === 'rejected' ||
            status === 'cancelled';

        const wasAlreadyRefundStatus =
            previousStatus === 'rejected' ||
            previousStatus === 'cancelled';

        if (
            isRefundStatus &&
            !wasAlreadyRefundStatus
        ) {
            const user = data.users.find(
                (item) =>
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

                data.transactions.push({
                    id: generateId(),
                    userId: user.id,
                    type: 'withdrawal_reversal',
                    amount: Number(
                        withdrawal.amount
                    ),
                    currency:
                        withdrawal.currency ||
                        user.currency ||
                        'NGN',
                    status: 'completed',
                    reference:
                        `RV-${generateId()}`,
                    description:
                        `Withdrawal reversed: ${withdrawal.reference}`,
                    createdAt:
                        new Date().toISOString()
                });
            }
        }

        writeData(data);

        return res.json({
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
    async (req, res, next) => {
        try {
            const form = parseBody(
                registerSchema,
                req.body,
                res
            );

            if (!form) {
                return;
            }

            const data = readData();

            const email =
                form.email
                    .trim()
                    .toLowerCase();

            const existing =
                data.users.find(
                    (item) =>
                        String(
                            item.email
                        )
                            .toLowerCase() ===
                        email
                );

            if (existing) {
                return res.status(409).json({
                    error:
                        'Account already exists'
                });
            }

            const hashedPassword =
                await bcrypt.hash(
                    form.password,
                    10
                );

            const user = {
                id: generateId(),
                fullName:
                    form.fullName.trim(),
                email,
                phone:
                    form.phone.trim(),
                password:
                    hashedPassword,
                balance: 0,
                currency: 'NGN',
                status: 'active',
                createdAt:
                    new Date().toISOString()
            };

            data.users.push(user);

            writeData(data);

            const token = jwt.sign(
                {
                    sub: user.id,
                    email: user.email
                },
                process.env.JWT_SECRET,
                {
                    expiresIn: '7d'
                }
            );

            return res.status(201).json({
                user: safeUser(user),
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
    async (req, res, next) => {
        try {
            const form = parseBody(
                loginSchema,
                req.body,
                res
            );

            if (!form) {
                return;
            }

            const data = readData();

            const email =
                form.email
                    .trim()
                    .toLowerCase();

            const user = data.users.find(
                (item) =>
                    String(item.email)
                        .toLowerCase() ===
                    email
            );

            if (!user) {
                return res.status(401).json({
                    error:
                        'Invalid credentials'
                });
            }

            const passwordCorrect =
                await bcrypt.compare(
                    form.password,
                    user.password
                );

            if (!passwordCorrect) {
                return res.status(401).json({
                    error:
                        'Invalid credentials'
                });
            }

            if (
                user.status !== 'active'
            ) {
                return res.status(403).json({
                    error:
                        'Account unavailable'
                });
            }

            const token = jwt.sign(
                {
                    sub: user.id,
                    email: user.email
                },
                process.env.JWT_SECRET,
                {
                    expiresIn: '7d'
                }
            );

            return res.json({
                user: safeUser(user),
                token
            });
        } catch (error) {
            next(error);
        }
    }
);

/* =========================================================
   GET USER PROFILE
========================================================= */

app.get(
    '/api/me',
    auth,
    (req, res) => {
        return res.json({
            user: safeUser(req.user)
        });
    }
);

/* =========================================================
   GET WALLET
========================================================= */

app.get(
    '/api/wallet',
    auth,
    (req, res) => {
        const data = readData();

        const user =
            data.users.find(
                (item) =>
                    item.id === req.user.id
            );

        if (!user) {
            return res.status(404).json({
                error: 'User not found'
            });
        }

        const transactions =
            data.transactions
                .filter(
                    (item) =>
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

        return res.json({
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
                    50
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
    (req, res) => {
        const data = readData();

        const loans =
            data.loans
                .filter(
                    (item) =>
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

        return res.json({
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
    (req, res, next) => {
        try {
            const form = parseBody(
                loanSchema,
                req.body,
                res
            );

            if (!form) {
                return;
            }

            const data = readData();

            const user =
                data.users.find(
                    (item) =>
                        item.id ===
                        req.user.id
                );

            if (!user) {
                return res.status(404).json({
                    error:
                        'User not found'
                });
            }

            const estimate =
                estimateLoan(
                    form.loanAmount,
                    form.loanPeriodYears
                );

            const loanApplication = {
                id: generateId(),
                userId: req.user.id,

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

                estimatedInterest:
                    estimate.interest,

                estimatedTotalRepayment:
                    estimate.total,

                estimatedMonthlyPayment:
                    estimate.monthly,

                createdAt:
                    new Date().toISOString(),

                updatedAt:
                    new Date().toISOString()
            };

            data.loans.push(
                loanApplication
            );

            writeData(data);

            return res
                .status(201)
                .json({
                    loan:
                        loanApplication
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
    (req, res) => {
        const data = readData();

        const withdrawals =
            data.withdrawals
                .filter(
                    (item) =>
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

        return res.json({
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
    (req, res, next) => {
        try {
            const form = parseBody(
                withdrawalSchema,
                req.body,
                res
            );

            if (!form) {
                return;
            }

            const data = readData();

            const user =
                data.users.find(
                    (item) =>
                        item.id ===
                        req.user.id
                );

            if (!user) {
                return res.status(404).json({
                    error:
                        'User not found'
                });
            }

            const balance =
                Number(
                    user.balance || 0
                );

            const amount =
                Number(form.amount);

            if (amount > balance) {
                return res.status(400).json({
                    error:
                        'Insufficient balance'
                });
            }

            /*
             Deduct immediately while
             withdrawal is pending.
            */
            user.balance =
                balance - amount;

            const reference =
                `WD-${generateId()}`;

            const withdrawal = {
                id: generateId(),
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
                createdAt:
                    new Date().toISOString(),
                updatedAt:
                    new Date().toISOString()
            };

            data.withdrawals.push(
                withdrawal
            );

            data.transactions.push({
                id: generateId(),
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
                    'Withdrawal request submitted',
                createdAt:
                    new Date().toISOString()
            });

            writeData(data);

            return res
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
   IMPORTANT: JSON API 404

   This is one of the important fixes for:

   Unexpected token '<',
   "<!DOCTYPE "... is not valid JSON

   Unknown /api paths now return JSON instead of HTML.
========================================================= */

app.use(
    '/api',
    (req, res) => {
        return res.status(404).json({
            error:
                'API endpoint not found',
            method:
                req.method,
            path:
                req.originalUrl
        });
    }
);

/* =========================================================
   STATIC FRONTEND

   Keep this AFTER the API routes.
========================================================= */

app.use(
    express.static(__dirname)
);

app.get('/', (req, res) => {
    return res.sendFile(
        path.join(
            __dirname,
            'index.html'
        )
    );
});

app.get('/admin', (req, res) => {
    return res.sendFile(
        path.join(
            __dirname,
            'admin.html'
        )
    );
});

/* =========================================================
   GENERAL 404
========================================================= */

app.use((req, res) => {
    /*
     Do not send HTML for API URLs.
    */
    if (
        req.originalUrl.startsWith(
            '/api'
        )
    ) {
        return res.status(404).json({
            error:
                'API endpoint not found'
        });
    }

    return res.status(404).send(
        'Page not found'
    );
});

/* =========================================================
   GLOBAL ERROR HANDLER

   API errors stay JSON.
========================================================= */

app.use(
    (err, req, res, next) => {
        console.error(
            '❌ Server error:',
            err
        );

        if (res.headersSent) {
            return next(err);
        }

        /*
         Invalid JSON sent to Express.
        */
        if (
            err instanceof SyntaxError &&
            err.status === 400 &&
            'body' in err
        ) {
            return res.status(400).json({
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
                        process.env
                            .NODE_ENV ===
                        'production'
                            ? 'Internal server error'
                            : err.message ||
                              'Internal server error'
                });
        }

        return res
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

app.listen(PORT, '0.0.0.0', () => {
    console.log('');
    console.log(
        '✅ Oceanic Lending API started'
    );

    console.log(
        `✅ Port: ${PORT}`
    );

    console.log(
        `✅ Health: /api/health`
    );

    console.log(
        `✅ Admin: /admin`
    );

    console.log('');
});
