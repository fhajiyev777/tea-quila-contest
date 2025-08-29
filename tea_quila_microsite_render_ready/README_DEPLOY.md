# Deploy to Render (quick)
1. Create a GitHub repo and upload all files in this folder.
2. Go to render.com → New → Web Service → Connect your repo.
3. Build command: `pip install -r requirements.txt`
4. Start command: `gunicorn app:app -b 0.0.0.0:$PORT`
5. Add environment variables (from `.env.example`): ADMIN_USER, ADMIN_PASS, SECRET_KEY.
6. Deploy. You will get a URL like `https://yourapp.onrender.com`.

## Squarespace iframe
In your Squarespace page, insert a Code block with:
```
<iframe src="https://YOUR_RENDER_URL" width="100%" height="1600" style="border:0;" loading="lazy"></iframe>
```
This build already allows framing from tea-quila.ca and Squarespace.
