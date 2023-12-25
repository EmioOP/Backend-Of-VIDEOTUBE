import mongoose,{Schema} from "mongoose";
import mongooseAggregatePaginate from "mongoose-aggregate-paginate-v2";

const videoSchema = new Schema({
    videoFile:{
        type:String, //url from cloudinary
        required:true
    },
    thumbnail:{
        type:String, // url from cloudinary
        required:true
    },
    title:{
        type:String,
        required:true
    },
    duration:{
        type:Number,
        required:true
    },
    views:{
        type:Number,
        default:true,
    },
    isPublished:{
        type:Boolean,
        default:true
    },
    owner:{
        type:Schema.Types.ObjectId,
        ref:"User"
    }

},{timestamps:true})

videoSchema.plugin(mongooseAggregatePaginate)

export const Video = mongoose.model("Video",videoSchema)