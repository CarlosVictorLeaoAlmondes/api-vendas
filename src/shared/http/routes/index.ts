import usersRouter from "@modules/users/routes/users.routes";
import { Router } from "express";
import productsRouter from "src/modules/products/routes/products.routes";

const routes = Router();

routes.use("/products", productsRouter);
routes.use("/users", usersRouter);

export default routes;
