import { ApiResponse } from "../utils/api-response.js";
import { asynchandler } from "../utils/async-handler.js";


// const healthcheck = async (req, res, next) => {
//     try {
//         const user = await getuserfromdb()
//         res.status(200).json(

//             new ApiResponse(200, {message: "Server is running"})
//         );
//     } catch (error) {
//         next(err)
        
//     }
// }


const healthcheck = asynchandler(async (req, res) => {
    res
    .status(200)
    .json(
        new ApiResponse(200, {message: "server is running"})
    )
})
export { healthcheck };