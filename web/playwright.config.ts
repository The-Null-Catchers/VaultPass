import {defineConfig} from "@playwright/test";
export default defineConfig({
  testDir:"./e2e", timeout:180000, workers:1, reporter:"list",
  use:{baseURL:"http://localhost:3000",viewport:{width:1440,height:1000}},
  webServer:[
    {command:"DATABASE_URL=sqlite:////tmp/vaultpass-e2e.db python -c 'from app.models import Base; from app.db import engine; Base.metadata.create_all(engine); import app.main as main; from app.security import rate_limit; main.app.dependency_overrides[rate_limit]=lambda:None; main.account_rate_limit=lambda _:None; import uvicorn; uvicorn.run(main.app,host=\"127.0.0.1\",port=8000,access_log=False)'",cwd:"../backend",port:8000,reuseExistingServer:!process.env.CI,timeout:120000},
    {command:"npm run dev -- --hostname 127.0.0.1",port:3000,reuseExistingServer:!process.env.CI,timeout:120000}
  ]
});
