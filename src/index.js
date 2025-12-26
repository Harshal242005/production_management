import dotenv from "dotenv";
import app from "./app.js";
import connctDB from "./db/index.js"



dotenv.config({
  path: "./.env",
});




const port = process.env.PORT || 3000;


connctDB()
  .then(() => {
    app.listen(port, () => {
      console.log(`Example app listening on port http://localhost:${port}`);
    });
  })
  .catch((err) => {
    console.error("MongoDB connection error", err);
    process.exit(1);
  });


// connctDB()
//   .then(() => {
//     console.log(`Example app listning on port http://localhost:${port}`);
    
//   })
//   .catch((err) => {
//     console.error("MongoDB connection error", err);
//     process.exit(1)
//   });

