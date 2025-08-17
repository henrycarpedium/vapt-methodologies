# VAPT Methodologies – Local Setup Guide

This guide will help you download (clone) the repository from GitHub and run it locally on your machine.

## Prerequisites
- [Node.js](https://nodejs.org/) (v16 or higher recommended)
- [npm](https://www.npmjs.com/) (comes with Node.js)
- [Git](https://git-scm.com/)

## 1. Clone the Repository

Open your terminal or command prompt and run:

```sh
git clone https://github.com/henrycarpedium/vapt-methodologies.git
cd vapt-methodologies
```

## 2. Install Dependencies

Install all required npm modules:

```sh
npm install
```

## 3. Start the Development Server

```sh
npm start
```

- The app will start on [http://localhost:3000](http://localhost:3000) by default.
- If port 3000 is busy, you will be prompted to use another port.

## 4. Build for Production (Optional)

To create an optimized production build:

```sh
npm run build
```

The build output will be in the `build/` directory.

## Troubleshooting
- If you encounter errors, ensure Node.js and npm are installed and up to date.
- Delete the `node_modules` folder and `package-lock.json`, then run `npm install` again if you have dependency issues.

---

**Repository:** https://github.com/henrycarpedium/vapt-methodologies

For any issues, please open an issue on GitHub or contact the maintainer.
