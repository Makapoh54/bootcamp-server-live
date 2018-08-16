import mongoose from 'mongoose';

const mediaSchema = new mongoose.Schema(
  {
    username: { type: String, required: true },
    path: { type: String, required: true },
  },
  { timestamps: true },
);

const MediaModel = mongoose.model('Media', mediaSchema);

const save = async model => new MediaModel(model).save();

const getMediaById = async id => MediaModel.findById(id);

const getMediaByUser = async username => MediaModel.findOne({ username });

export { save, getMediaById, getMediaByUser };
