import mongoose, { Schema } from "mongoose";
import mongooseAggregatePaginate from "mongoose-aggregate-paginate-v2";

const videoSchema = new Schema(
    {
        videoFile: {
            type: String,
            required: [true, 'Video is required']
        },
        thumbnail: {
            type: String,
            required: [true, 'Video thumbnail is required']
        },
        title: {
            type: String,
            required: [true, 'Video title is required']
        },
        discription: {
            type: String,
            required: [true, 'Video title is required']
        },
        duration: {
            type: Number,
            required: true
        },
        views: {
            type: Number,
            default: 0
        },
        isPublished: {
            type: true,
            default: true
        },
        owner: {
            type: Schema.Types.ObjectId,
            ref: 'User'
        }

    },
    { timestamps: true }
)

videoSchema.plugin(mongooseAggregatePaginate)
export const Video = mongoose.model('Video', videoSchema)