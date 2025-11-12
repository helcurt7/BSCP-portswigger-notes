Ah! Got it — you want **exactly how HTML input attributes (`name`, `id`, `value`) map to what gets sent to the backend** in your Express app. Let’s break it down carefully.

---

## **1. How form data is sent in HTML → Express**

When a form is submitted:

```html
<form action="/someRoute" method="post">
  <input type="text" name="myName" value="Hello">
  <button type="submit">Submit</button>
</form>
```

* **`name`** → the key sent to the backend (`req.body.myName`)
* **`value`** → the data associated with that key (`req.body.myName === "Hello"`)
* **`id`** → only used in the frontend for **JavaScript or CSS**. It is **not sent automatically** to the backend.

---

### **2. Your app example**

#### **Delete item**

```html
<input type="checkbox" onchange="this.form.submit()" name="deleteItemId" value="<%= item.id %>">
```

* `name="deleteItemId"` → backend sees it as `req.body.deleteItemId`
* `value="<%= item.id %>"` → the value sent (e.g., `1`, `2`)
* `id` (not here) → irrelevant for form submission

**Backend:**

```js
const id = req.body.deleteItemId; // gets value from the checkbox
await db.query("DELETE FROM items WHERE id = $1", [id]);
```

---

#### **Edit item**

```html
<input type="hidden" name="updatedItemId" value="<%= item.id %>">
<input type="text" name="updatedItemTitle" value="<%= item.title %>">
```

* `updatedItemId` → sent as `req.body.updatedItemId`
* `updatedItemTitle` → sent as `req.body.updatedItemTitle`

**Backend:**

```js
const id = req.body.updatedItemId;      // gets the item id
const title = req.body.updatedItemTitle; // gets new title
await db.query("UPDATE items SET title = $1 WHERE id = $2", [title, id]);
```

---

#### **Add item**

```html
<input type="text" name="newItem" value="">
<button type="submit" name="list" value="<%=listTitle%>">+</button>
```

* `newItem` → backend sees `req.body.newItem`
* `list` → backend sees `req.body.list`
* `id` attribute (if present) → frontend only, not sent

**Backend:**

```js
const item = req.body.newItem; // value typed by user
const listName = req.body.list; // value from button
await db.query("INSERT INTO items (title) VALUES ($1)", [item]);
```

---

### **3. Rules**

1. **`name`** → key in `req.body`
2. **`value`** → the data for that key
3. **`id`** → purely frontend, used for JS (`document.getElementById()`) or CSS, **not sent**
4. Only **form elements with `name`** will send data to the backend.
5. Buttons with `name` and `value` also send data **when clicked to submit**.

---

💡 **Tip:** In your app, the checkbox `onchange="this.form.submit()"` automatically sends the value of that checkbox as `deleteItemId` without needing a submit button.

---

If you want, I can make a **table with every single input in your code** showing exactly **name → req.body key, value → what’s sent, id → frontend only** for your GitHub writeup. That would be a clean reference.

Do you want me to do that?
