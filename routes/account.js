const express = require('express');
const router = express.Router();
const User = require('../models/user');
const Order = require('../models/Order');
const passport = require('passport'); 
const bcrypt = require('bcryptjs');
const { isAdmin } = require('../middleware');


router.post('/make-admin/:id', isAdmin, async (req, res) => {
  try {
    const userId = req.params.id;
    await User.findByIdAndUpdate(userId, { isAdmin: true });
    res.json({ message: 'User role updated to admin' });
  } catch (error) {
    console.error('Error updating user role:', error);
    res.status(500).send('Error updating user role');
  }
});

router.post('/register', async (req, res) => {
    const { firstName, lastName, email, password, confirmpassword } = req.body;
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const nameRegex = /^[a-zA-ZÀ-ỹ\s]+$/;

    const errors = [];

    if (!firstName || !lastName || !email || !password || !confirmpassword) {
        errors.push('Vui lòng điền đầy đủ tất cả các trường.');
    }
    if (firstName && !nameRegex.test(firstName)) {
        errors.push('Họ không hợp lệ (không chứa ký tự đặc biệt hoặc số).');
    }
    if (lastName && !nameRegex.test(lastName)) {
        errors.push('Tên không hợp lệ (không chứa ký tự đặc biệt hoặc số).');
    }
    if (email && !emailRegex.test(email)) {
        errors.push('Email không hợp lệ.');
    }
    if (password.length < 6) {
        errors.push('Mật khẩu phải có ít nhất 6 ký tự.');
    }
    if (password.length > 13) {
        errors.push('Mật khẩu không được dài quá 13 ký tự.');
    }
    if (!/\d/.test(password)) {
        errors.push('Mật khẩu phải chứa ít nhất một số.');
    }
    if (!/[A-Z]/.test(password)) {
        errors.push('Mật khẩu phải có ít nhất một chữ in hoa.');
    }
    if (password !== confirmpassword) {
        errors.push('Mật khẩu xác nhận không khớp.');
    }

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            errors.push('Email đã được đăng ký.');
        }

        if (errors.length > 0) {
            return res.render('register', { error: errors.join('<br>') });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const newUser = new User({
            firstName,
            lastName,
            email,
            password: hashedPassword
        });
        await newUser.save();
        req.flash('success', 'Đăng ký thành công! Vui lòng đăng nhập.');
        return res.redirect('/login');
    } catch (error) {
        console.error('Lỗi đăng ký:', error);
        return res.status(500).render('register', { error: 'Lỗi máy chủ. Vui lòng thử lại sau.' });
    }
});



router.post("/login", async (req, res) => {
    const { email, password } = req.body;
    const errors = [];

    if (!email || !password) {
        errors.push('Vui lòng nhập email và mật khẩu.');
    }
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        errors.push('Email không đúng định dạng.');
    }
    if (password && password.length < 6) {
        errors.push('Mật khẩu quá ngắn (ít nhất 6 ký tự).');
    }
    if (password && password.length > 13) {
        errors.push('Mật khẩu quá dài (tối đa 13 ký tự).');
    }

    try {
        const user = await User.findOne({ email });
        if (!user) {
            errors.push('Email không tồn tại.');
        }

        if (user) {
            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                errors.push('Mật khẩu không chính xác.');
            }
        }

        if (errors.length > 0) {
            return res.status(401).render('login', { error: errors.join('<br>') });
        }

        req.session.user = {
            _id: user._id,
            firstName: user.firstName,
            lastName: user.lastName,
            email: user.email,
            isAdmin: user.isAdmin
        };
        req.session.name = user.lastName + " " + user.firstName;

        req.session.save(err => {
            if (err) {
                return res.status(500).render('login', { error: 'Không thể lưu phiên đăng nhập.' });
            }
            return res.redirect("/");
        });
    } catch (error) {
        console.error('Lỗi đăng nhập:', error);
        return res.status(500).render('login', { error: 'Lỗi máy chủ. Vui lòng thử lại sau.' });
    }
});


router.post('/change-password', async (req, res) => {
    const { currentPassword, newPassword, confirmNewPassword } = req.body;
    const sessionUser = req.session.user;

    if (!sessionUser) {
        return res.redirect('/login');
    }

    const errors = [];

    if (!currentPassword || !newPassword || !confirmNewPassword) {
        errors.push('Vui lòng điền đầy đủ thông tin.');
    }

    try {
        const currentUser = await User.findOne({ email: sessionUser.email });
        if (!currentUser) {
            errors.push('Người dùng không tồn tại.');
        }

        if (currentUser && !(await bcrypt.compare(currentPassword, currentUser.password))) {
            errors.push('Mật khẩu hiện tại không chính xác.');
        }

        if (newPassword && currentPassword === newPassword) {
            errors.push('Mật khẩu mới không được trùng với mật khẩu hiện tại.');
        }

        if (newPassword !== confirmNewPassword) {
            errors.push('Mật khẩu xác nhận không khớp.');
        }

        if (newPassword && newPassword.length < 6) {
            errors.push('Mật khẩu mới phải có ít nhất 6 ký tự.');
        }

        if (newPassword && newPassword.length > 13) {
            errors.push('Mật khẩu mới không được vượt quá 13 ký tự.');
        }

        if (newPassword && !/[A-Z]/.test(newPassword)) {
            errors.push('Mật khẩu mới phải chứa ít nhất một chữ cái in hoa.');
        }

        if (newPassword && !/[a-z]/.test(newPassword)) {
            errors.push('Mật khẩu mới phải chứa ít nhất một chữ cái thường.');
        }

        if (newPassword && !/\d/.test(newPassword)) {
            errors.push('Mật khẩu mới phải chứa ít nhất một chữ số.');
        }

        if (errors.length > 0) {
            return res.render('account', { error: errors.join('<br>'), user: sessionUser });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);
        currentUser.password = hashedPassword;
        await currentUser.save();

        return res.render('account', { success: 'Đổi mật khẩu thành công.', user: sessionUser });

    } catch (error) {
        console.error('Lỗi đổi mật khẩu:', error);
        return res.render('account', { error: 'Lỗi máy chủ. Vui lòng thử lại sau.', user: sessionUser });
    }
});


router.get('/', async (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    try {
        const user = req.session.user;
        const orders = await Order.find({ user: user._id }).sort({ createdAt: -1 });
        res.render('account', { user, orders });
    } catch (error) {
        console.error('Lỗi khi lấy đơn hàng:', error);
        res.render('account', { user: req.session.user, error: 'Lỗi khi lấy đơn hàng.' });
    }
});

module.exports = router;
