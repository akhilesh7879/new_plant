const jwt = require("jsonwebtoken");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

exports.createOrderSession = async (req, res, next) => {
  try {
    const userId = req.user;
    const { cartOrProducts, shippingInfo, pricing } = req.body;

    // Generate JWT token with user ID
    const token = jwt.sign(
      { userId: userId.toString() },
      process.env.SECRET_KEY,
      { expiresIn: "30m" }
    );

    // The data that would be saved in Redis should now be handled without Redis storage.

    // CLEANUP_TASK:: REMOVE THE DATA FROM THE ORDER_SESSION_DATA :: PAYMENT_INFORMATION
    // In this version, we're skipping Redis calls for storage, focusing on token creation and sending back to the client.

    // Send success response
    const info = {
      status: true,
      message: "Successfully created the order session.",
      orderToken: token,
    };
    res.status(200).send(info);
  } catch (error) {
    next(error); // Pass the error to the global error handling middleware
  }
};

exports.getOrderSession = async (req, res, next) => {
  try {
    // Send success response if order session is active
    const info = {
      status: true,
      message: "Order Session is active!",
    };
    res.status(200).send(info);
  } catch (error) {
    // Pass error to error handling middleware
    next(error);
  }
};

exports.addShippingInfo = async (req, res, next) => {
  try {
    const userId = req.orderUser;
    const shipping = req.body;

    // Example: Save shipping info directly in the database
    const user = await userModel.findById(userId);

    if (!user) {
      const error = new Error("User not found");
      error.statusCode = 404;
      throw error;
    }

    // Assuming 'shippingInfo' is an array or field in the user schema
    user.shippingInfo = shipping;

    // Save updated user information
    await user.save();

    // Create response object
    const info = {
      status: true,
      message: "Successfully added the Shipping info.",
    };

    // Send response
    res.status(200).send(info);
  } catch (error) {
    // Pass error to error handling middleware
    next(error);
  }
};

exports.getShippingInfo = async (req, res, next) => {
  try {
    const userId = req.orderUser;

    // Retrieve shipping information from the database
    const user = await userModel.findById(userId);

    if (!user) {
      const error = new Error("User not found");
      error.statusCode = 404;
      throw error;
    }

    // Check if the user has shipping information
    if (!user.shippingInfo) {
      const error = new Error("Shipping information not found.");
      error.statusCode = 404;
      throw error;
    }

    // Create response object if shipping information is available
    const info = {
      status: true,
      message: "Shipping information retrieved successfully.",
      result: user.shippingInfo,
    };

    // Send success response
    res.status(200).send(info);
  } catch (error) {
    // Pass error to error handling middleware
    next(error);
  }
};

exports.confirmOrder = async (req, res, next) => {
  try {
    const userId = req.orderUser;

    // Retrieve order details directly from the database
    const user = await userModel.findById(userId);

    if (!user) {
      const error = new Error("User not found");
      error.statusCode = 404;
      throw error;
    }

    // Check if the user has cart, shipping, and pricing info
    if (!user.cartOrProducts || !user.shippingInfo || !user.pricing) {
      const error = new Error("Order Session data is missing or incomplete");
      error.statusCode = 400;
      throw error;
    }

    // Create response object with shipping address, cart or product info, and pricing
    const info = {
      status: true,
      message: "Order Session is active.",
      result: {
        address: user.shippingInfo,
        cartOrProducts: user.cartOrProducts,
        pricing: user.pricing,
      },
    };

    // Send success response
    res.status(200).send(info);
  } catch (error) {
    // Pass error to error handling middleware
    next(error);
  }
};

exports.processPayment = async (req, res, next) => {
  try {
    const userId = req.orderUser;

    // Retrieve shipping information and pricing from the database
    const user = await userModel.findById(userId);

    if (!user) {
      const error = new Error("User not found");
      error.statusCode = 404;
      throw error;
    }

    // Check if shipping and pricing information exist
    if (!user.shippingInfo || !user.pricing) {
      const error = new Error("Invalid Order Session.");
      error.statusCode = 403;
      throw error;
    }

    // Check if payment info already exists in the database
    if (user.paymentInfo) {
      const info = {
        status: true,
        message: "Payment already created.",
        result: user.paymentInfo,
      };
      return res.status(200).send(info);
    }

    // Create payment intent with shipping info and pricing
    const myPayment = await stripe.paymentIntents.create({
      description: "Plant Selling website",
      shipping: {
        name: user.shippingInfo.name,
        address: {
          line1: user.shippingInfo.address,
          postal_code: user.shippingInfo.pinCode,
          city: user.shippingInfo.city,
          state: user.shippingInfo.state,
          country: "India", // Setting the default country.
        },
      },
      amount: user.pricing.totalPrice * 100,
      currency: "inr",
      metadata: {
        company: "PlantSeller",
        user: user.shippingInfo.user,
      },
    });

    const paymentData = {
      paymentId: myPayment.id,
      client_secret: myPayment.client_secret,
      amount: user.pricing.totalPrice * 100,
      paymentMethods: myPayment.payment_method_types[0],
    };

    // Store the payment data in the user's record in the database
    user.paymentInfo = paymentData;
    await user.save();

    // Send payment response
    if (myPayment) {
      const info = {
        status: true,
        message: "Payment intent created.",
        result: paymentData,
      };
      return res.status(200).send(info);
    } else {
      const info = {
        status: false,
        message: "Payment not completed.",
      };
      return res.status(400).send(info);
    }
  } catch (error) {
    // Pass error to error handling middleware
    next(error);
  }
};

exports.getStripePublicKey = async (req, res, next) => {
  try {
    if (req.orderUser) {
      const stripeApiKey = process.env.STRIPE_PUBLISHABLE_KEY;

      if (!stripeApiKey) {
        const error = new Error("Stripe public key is not configured");
        error.statusCode = 500;
        throw error;
      }

      const info = {
        status: true,
        message: "Sending the stripe public key.",
        result: { stripeApiKey },
      };

      res.status(200).send(info);
    } else {
      const info = {
        status: false,
        message: "Authentication Failed",
      };
      res.status(403).send(info);
    }
  } catch (error) {
    next(error); //! Pass the error to the global error middleware
  }
};
