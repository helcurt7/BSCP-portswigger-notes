Here is the absolute core mechanism for passing data back and forth using JSON. No fluff, just the exact bridge.

### 1. Frontend → Backend (Sending Data to the Server)

**The React Side (The Sender):**
You must stringify the data and set the `Content-Type` header.

```javascript
// React component
const sendData = async () => {
  const payload = { taskName: "Learn API" };

  await fetch('http://localhost:5000/api/data', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload) // Packs the JS object into a JSON string
  });
};

```

**The Express Side (The Receiver):**
You must have the JSON middleware to unpack the body.

```javascript
// Express server
app.use(express.json()); // REQUIRED: Unpacks the JSON string back into an object

app.post('/api/data', (req, res) => {
  const { taskName } = req.body; // Unpacks exactly what React sent
  console.log(taskName); 
  
  res.status(200).json({ status: "Received!" });
});

```

---

### 2. Backend → Frontend (Pulling Data to the Client)

**The Express Side (The Sender):**
You use `res.json()` to send data (like database rows) out to the client.

```javascript
// Express server
app.get('/api/data', async (req, res) => {
  const myData = [
    { id: 1, title: "Task One" },
    { id: 2, title: "Task Two" }
  ];
  
  res.json(myData); // Automatically converts the array/object to JSON and sends it
});

```

**The React Side (The Receiver):**
You make a `GET` request (default for fetch) and parse the response.

```javascript
// React component
const fetchData = async () => {
  const response = await fetch('http://localhost:5000/api/data');
  const data = await response.json(); // REQUIRED: Unpacks the JSON back into a JS array/object
  
  console.log(data); // [{ id: 1, title: "Task One" }, ...]
};

```

Would you like the specific React `useEffect` snippet that runs this `fetchData` function automatically the second your page loads?
