import mongoose from "mongoose";
import { v4 as uuidv4 } from "uuid";

const participantSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  connectionId: {
    type: String,
    default: null,
  },
  joinedAt: {
    type: Date,
    default: Date.now,
  },
  leftAt: {
    type: Date,
    default: null,
  },
  duration: {
    type: Number,
    default: 0,
  },
});

const chatMessageSchema = new mongoose.Schema({
  messageId: {
    type: String,
    default: () => uuidv4(),
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  username: {
    type: String,
    required: true,
  },
  text: {
    type: String,
    required: true,
    maxlength: [1000, "Message must be less than 1000 characters"],
  },
  timestamp: {
    type: Date,
    default: Date.now,
  },
});

const roomSchema = new mongoose.Schema({
  roomId: {
    type: String,
    required: true,
    unique: true,
    default: () => uuidv4().substring(0, 8),
  },
  name: {
    type: String,
    required: [true, "Room name is required"],
    trim: true,
    maxlength: [100, "Room name must be less than 100 characters"],
  },
  description: {
    type: String,
    trim: true,
    maxlength: [500, "Description must be less than 500 characters"],
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  accessToken: {
    type: String,
    default: () => uuidv4(),
  },
  isPublic: {
    type: Boolean,
    default: false,
  },
  maxParticipants: {
    type: Number,
    default: 6,
    min: 2,
    max: 10,
  },
  isActive: {
    type: Boolean,
    default: true,
  },
  participants: [participantSchema],
  currentParticipants: {
    type: Number,
    default: 0,
  },
  // AUDIT: Cap messages to prevent unbounded document growth (16MB BSON limit)
  messages: {
    type: [chatMessageSchema],
    validate: [
      {
        validator: function (val) {
          return val.length <= 500;
        },
        message: "Chat history is limited to 500 messages per room",
      },
    ],
  },
  sessionId: {
    type: String,
    default: null,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  closedAt: {
    type: Date,
    default: null,
  },
});

roomSchema.index({ roomId: 1 });
roomSchema.index({ createdBy: 1 });
roomSchema.index({ isActive: 1 });

const Room = mongoose.model("Room", roomSchema);

export default Room;
