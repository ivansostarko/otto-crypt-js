# How to Publish an NPM Package


---

## 🧩 1. Prepare project
Make sure your project has a proper structure like this:

```
my-package/
├── package.json
├── index.js
├── README.md
├── LICENSE
└── .gitignore
```

**`package.json`** is the most important file.  
You can create it by running:

```bash
npm init
```

Then answer the prompts (or use `npm init -y` to skip and use defaults).

---

## 🪪 2. Set the package name
In your `package.json`, make sure:
- `"name"` is unique (check on [https://www.npmjs.com/](https://www.npmjs.com/))
- `"version"` follows [semver](https://semver.org/) (e.g., `1.0.0`)
- `"main"` points to your entry file (e.g., `"main": "index.js"`)

Example:

```json
{
  "name": "my-awesome-package",
  "version": "1.0.0",
  "description": "A simple utility for awesome things",
  "main": "index.js",
  "author": "Your Name",
  "license": "MIT"
}
```

---

## 🔐 3. Log in to npm
If you don’t have an npm account yet, create one first:

```bash
npm adduser
```

Or log in:

```bash
npm login
```

You’ll be asked for your **username**, **password**, and **email**.

---

## 📦 4. Publish the package

Once logged in, simply run:

```bash
npm publish
```

That’s it! 🎉  
Your package will be live on **npmjs.com**.

---

## ⚙️ 5. (Optional) Publish under a scope

If you want to publish under a **scope** (like `@yourname/package`):

1. Change the name in `package.json`:
   ```json
   "name": "@yourname/my-package"
   ```
2. Publish as a **public** package (default is private):
   ```bash
   npm publish --access public
   ```

---

## 🧹 6. Update your package

When you make changes and want to publish a new version:

1. Bump the version:
   ```bash
   npm version patch
   # or npm version minor / major
   ```
2. Publish again:
   ```bash
   npm publish
   ```

---

## 🚫 Common issues

- **“You do not have permission to publish”**  
  → The package name is already taken.

- **“Cannot publish private package”**  
  → Add `--access public` for scoped packages.

- **Forgot to add `.npmignore` or `.gitignore`**  
  → Use `.npmignore` to exclude files you don’t want to publish (tests, local config, etc.).

---

