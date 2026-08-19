const Product = require('../models/Product');
const { StatusCodes } = require('http-status-codes');
const CustomError = require('../errors');
const path = require('path');
const crypto = require('crypto');

const ALLOWED_PRODUCT_FIELDS = [
  'name',
  'price',
  'description',
  'image',
  'category',
  'company',
  'colors',
  'featured',
  'freeShipping',
  'inventory',
];

const pickAllowedFields = (body, allowedFields) => {
  const result = {};
  for (const field of allowedFields) {
    if (body[field] !== undefined) {
      result[field] = body[field];
    }
  }
  return result;
};

const createProduct = async (req, res) => {
  const productData = pickAllowedFields(req.body, ALLOWED_PRODUCT_FIELDS);
  productData.user = req.user.userId;
  const product = await Product.create(productData);
  res.status(StatusCodes.CREATED).json({ product });
};
const getAllProducts = async (req, res) => {
  const products = await Product.find({});

  res.status(StatusCodes.OK).json({ products, count: products.length });
};
const getSingleProduct = async (req, res) => {
  const { id: productId } = req.params;

  const product = await Product.findOne({ _id: productId }).populate('reviews');

  if (!product) {
    throw new CustomError.NotFoundError(`No product with id : ${productId}`);
  }

  res.status(StatusCodes.OK).json({ product });
};
const updateProduct = async (req, res) => {
  const { id: productId } = req.params;
  const productData = pickAllowedFields(req.body, ALLOWED_PRODUCT_FIELDS);

  const product = await Product.findOneAndUpdate({ _id: productId }, productData, {
    new: true,
    runValidators: true,
  });

  if (!product) {
    throw new CustomError.NotFoundError(`No product with id : ${productId}`);
  }

  res.status(StatusCodes.OK).json({ product });
};
const deleteProduct = async (req, res) => {
  const { id: productId } = req.params;

  const product = await Product.findOne({ _id: productId });

  if (!product) {
    throw new CustomError.NotFoundError(`No product with id : ${productId}`);
  }

  await product.remove();
  res.status(StatusCodes.OK).json({ msg: 'Success! Product removed.' });
};
const ALLOWED_IMAGE_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];

const uploadImage = async (req, res) => {
  if (!req.files) {
    throw new CustomError.BadRequestError('No File Uploaded');
  }
  const productImage = req.files.image;

  if (!productImage.mimetype.startsWith('image')) {
    throw new CustomError.BadRequestError('Please Upload Image');
  }

  const maxSize = 1024 * 1024;

  if (productImage.size > maxSize) {
    throw new CustomError.BadRequestError(
      'Please upload image smaller than 1MB'
    );
  }

  const fileExtension = path.extname(productImage.name).toLowerCase();
  if (!ALLOWED_IMAGE_EXTENSIONS.includes(fileExtension)) {
    throw new CustomError.BadRequestError('Unsupported image type');
  }

  // never trust the client-supplied filename for the on-disk path - generate
  // our own to eliminate path traversal and filename collisions entirely
  const safeFileName = `${crypto.randomBytes(16).toString('hex')}${fileExtension}`;
  const imagePath = path.join(__dirname, '../public/uploads/', safeFileName);
  await productImage.mv(imagePath);
  res.status(StatusCodes.OK).json({ image: `/uploads/${safeFileName}` });
};

module.exports = {
  createProduct,
  getAllProducts,
  getSingleProduct,
  updateProduct,
  deleteProduct,
  uploadImage,
};
