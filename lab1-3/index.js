const fs = require('fs').promises;
const fsSync = require('fs');
const express = require('express');
const handlebars = require("handlebars");
const session = require('express-session')
const path = require('path')
const bcrypt = require('bcrypt');

const pathUser = path.join(__dirname, 'file', 'user.json');
const pathAccess = path.join(__dirname, 'file', 'accessFile.json');
let users = require(pathUser);
let access = require(pathAccess);
const app = express();

app.use(express.urlencoded());
app.use(express.json());
app.use(session({ secret: 'keyboard cat123123', cookie: { maxAge: 60 * 60 * 1000 } }));

function log(args) {
    fs.appendFile(path.join(__dirname, 'log', 'access.log'), JSON.stringify(args) + '\n').catch(err => console.error(err));
}

const autentification = {};

async function updatefile(path, body) {
    return fs.writeFile(path, JSON.stringify(body, null, 2));
}

async function updateUsers() {
    delete require.cache[require.resolve(pathUser)];
    access = require(pathUser);
}

async function updateAccess() {
    delete require.cache[require.resolve(pathAccess)];
    access = require(pathAccess);
    // return updatefile(pathAccess, access);
}

app.get('/login', async (req, res) => {
    if (req.session.user) {
        return res.redirect('/file');
    }
    const html = (await fs.readFile('view/login.html')).toString();
    const parseHtml = handlebars.compile(html);
    return res.end(parseHtml({ error: req.query.error }));
});

app.post('/login', async (req, res) => {
    const user = users.find(e => e.login === req.body.login);
    if (!user) {
        log({cdate: new Date(), uid:req.body.login, originalUrl: req.originalUrl, ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress, sessionID: req.sessionID, message: 'user not found'});
        return res.redirect('login?error=wrong_user1');
    }
    if (user.password) {
        return res.status(400).send('Користувач не підтверджений');
    }
    const result = await bcrypt.compare(req.body.password, user.hash);
    if (result) {
        req.session.user = user;
        autentification[req.sessionID] = { date: new Date() };
        return res.redirect('/file');
    }
    log({cdate: new Date(), uid:user.login, originalUrl: req.originalUrl, ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress, sessionID: req.sessionID, message: 'wrond password user'});
    return res.redirect('login?error=wrong_user2');
});


app.post('/auth/create', async (req, res) => {
    try {
        const login = req.body.login;
        const password = req.body.password;
        const createdUser = users.find(u => u.login === login);
        if (createdUser) {
            log({cdate: new Date(), uid: req.body.login, originalUrl: req.originalUrl, ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress, sessionID: req.sessionID, message: 'user already exists'});
            return res.status(400).send('User already exists');
        }
        users.push({ login, password, admin: false, hash: await bcrypt.hash(password, await bcrypt.genSalt()) });
        return res.send('Заявка надіслана');
    } finally {
        await updatefile(pathUser, users);
    }
});

app.get('/logout', async (req, res) => {
    req.session.destroy()
    return res.redirect('login');
});

app.get('/auth/get_answer', async (req, res) => {
    return res.send(`Дайте відповідь на питання. ${autentification[req.sessionID].question}`);
});

app.post('/auth/get_answer', async (req, res) => {
    const user = users.find(u => u.login === req.session.user.login);
    const answer = req.body.answer;
    if (await bcrypt.compare(answer, user.ask[autentification[req.sessionID].question])) {
        const prevHref = autentification[req.sessionID].originalUrl;
        autentification[req.sessionID] = { date: new Date() };
        return res.redirect(prevHref);
    }
    log({cdate: new Date(), uid:user.login, originalUrl: req.originalUrl, ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress, sessionID: req.sessionID, message: 'wrond answer'});
    return res.status(400).send('Відповідь не правильна');
});

app.use(express.static('public'));

app.use((req, res, next) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    if (autentification[req.sessionID].question) {
        return res.redirect('/auth/get_answer');
    }
    if (new Date() - new Date(autentification[req.sessionID].date) > 1000 * 60 * 2) {
        const user = users.find(user => user.login === req.session.user.login);
        const questions = Object.keys(user.ask);
        if(questions.length < 2) {
            req.session.destroy()
            return res.status(403).send('Додайте питання до вашого акаунту. Поки вас буде розлогінено');
        }
        const quetion = questions[Math.floor(Math.random() * questions.length)];
        autentification[req.sessionID].question = quetion;
        autentification[req.sessionID].originalUrl = req.originalUrl;
        return res.redirect('/get_answer');
    }
    next();
});

async function isExist(file) {
    return new Promise(response => {
        fsSync.lstat(file, (err, stats) => {
            response(stats);
        })
    })
}

app.post('/auth/add_ask', async (req, res) => {
    try {
        const question = req.body.question;
        const answer = req.body.answer;
        const user = users.find(u => u.login === req.session.user.login);
        user.ask ||= {};
        user.ask[question] = await bcrypt.hash(answer, await bcrypt.genSalt());
        return res.send('Питання додано');
    } finally {
        await updatefile(pathUser, users);
    }
});

async function getFile(fullPath) {
    const preListFile = await fs.readdir(fullPath, { withFileTypes: true });
    const listFile = preListFile
        .map((e) => ({ name: e.name, isDirectory: e.isDirectory() }))
        .sort((a, b) => b.isDirectory ? 1 : -1);
    return listFile;
}

app.get('/file*', async (req, res) => {
    const fullPath = path.join(__dirname, 'file', req.params[0]);
    const info = await isExist(fullPath);
    if (!info) {
        return res.redirect('/file');
    }
    const html = (await fs.readFile('view/main.html')).toString();
    const parseHtml = handlebars.compile(html);
    let reqPath = req.path.replace(/\/*$/, '');
    const listFile = [];
    let body = '';
    let pathDir = fullPath;
    if (!info.isDirectory()) {
        pathDir = path.dirname(pathDir);
        reqPath = path.dirname(reqPath);
        if (req.session.user.admin || access.find(acFile => fullPath.includes(acFile.filename))?.allow !== 'admin') {
            body = await fs.readFile(fullPath) || ' ';
        } else {
            log({cdate: new Date(), uid:req.session.user.login, originalUrl: req.originalUrl, ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress, sessionID: req.sessionID, message: 'file protected'});
        }
    }
    if (reqPath != '/file') {
        listFile.push({ name: '..' });
    }
    listFile.push(...await getFile(pathDir));

    let filteredListFile = listFile;
    if (!req.session.user.admin) {
        filteredListFile = listFile.filter(file => access.find(acFile => acFile.filename === file.name)?.allow !== 'admin');
        console.log(filteredListFile, access);
    }

    const fullPathFile = filteredListFile.map(e => (e.fullPath = path.join(reqPath, e.name), e));
    return res.end(parseHtml({ listFile: fullPathFile, body }));
});

app.post('/file*', async (req, res) => {
    const fullPath = path.join(__dirname, 'file', req.params[0]);
    const info = await isExist(fullPath);
    if (!info) {
        return res.redirect('/file');
    }
    if (!req.session.user.admin) {
        log({cdate: new Date(), uid:req.session.user.login, originalUrl: req.originalUrl, ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress, sessionID: req.sessionID, message: 'dont have permission'});
        return res.status(403).end('You do not have permission to edit')
    }
    await fs.writeFile(fullPath, req.body.body);

    await updateUsers();
    await updateAccess();

    return res.redirect(req.path);
});


app.get('/', async (req, res) => {
    res.redirect('/file');
})

app.listen(3000);