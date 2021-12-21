const fs = require('fs').promises;
const fsSync = require('fs');
const express = require('express');
const handlebars = require("handlebars");
const session = require('express-session')
const path = require('path')
const bcrypt = require('bcrypt');
const users = require('./user.json');
const app = express();

app.use(express.urlencoded());
app.use(express.json());
app.use(session({ secret: 'keyboard cat123123', cookie: { maxAge: 60000 } }))

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
    if(!user) {
        return res.redirect('login?error=wrong_user1');
    }
    const result = await bcrypt.compare(req.body.password, user.hash);
    if (result) {
        req.session.user = user;
        return res.redirect('/file');
    }
    return res.redirect('login?error=wrong_user2');
});

app.get('/logout', async (req, res) => {
    req.session.destroy()
    return res.redirect('login');
});

app.use(express.static('public'));

app.use((req, res, next) => {
    if (!req.session.user) {
        return res.redirect('/login');
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
    const reqPath = req.path.replace(/\/*$/, '');
    const listFile = [];
    if (reqPath != '/file') {
        listFile.push({name: '..'});
    }
    if(info.isDirectory()){
        listFile.push(...await getFile(fullPath));
        return res.end(parseHtml({ listFile, path: reqPath }));
    }
    listFile.push(...await getFile(path.dirname(fullPath)));
    const body = await fs.readFile(fullPath) || ' ';
    return res.end(parseHtml({ listFile, path: path.dirname(reqPath), body }));
});

app.post('/file*', async (req, res) => {
    const fullPath = path.join(__dirname, 'file', req.params[0]);
    const info = await isExist(fullPath);
    if (!info) {
        return res.redirect('/file');
    }
    if(!req.session.user.admin) {
        return res.status(403).end('You do not have permission to edit')
    }
    console.log(req.body);
    await fs.writeFile(fullPath, req.body.body);
    return res.redirect(req.path);
});


app.get('/', async (req, res) => {
    res.redirect('/file');
})

app.listen(3000);