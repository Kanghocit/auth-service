import mongoose from "mongoose";

const productSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, "Name is required"],
      trim: true,
      maxlength: [100, "Name must be less than 100 characters"],
      minlength: [3, "Name must be at least 3 characters long"],
    },
    image: {
      type: String,
    },
    brand: {
      type: String,
      required: [true, "Brand is required"],
      trim: true,
      maxlength: [100, "Brand must be less than 100 characters"],
      minlength: [3, "Brand must be at least 3 characters long"],
    },
    category: {
      type: String,
      required: [true, "Category is required"],
      trim: true,
      maxlength: [100, "Category must be less than 100 characters"],
      minlength: [3, "Category must be at least 3 characters long"],
    },
    discount: {
      type: Number,
      min: [0, "Discount must be greater than 0"],
      max: [100, "Discount must be less than 100"],
    },

    slug: {
      type: String,
      required: [true, "Slug is required"],
      unique: true,
      lowercase: true,
    },
    description: {
      type: String,
      required: [true, "Description is required"],
      trim: true,
      maxlength: [1000, "Description must be less than 1000 characters"],
    },
    price: {
      type: Number,
      required: [true, "Price is required"],
      min: [0, "Price must be greater than 0"],
    },
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: [true, "User is required"],
    },
    createdAt: {
      type: Date,
      default: Date.now,
    },
  },
  {
    timestamps: true,
  }
);

const Product = mongoose.model("Product", productSchema);

export default Product;
