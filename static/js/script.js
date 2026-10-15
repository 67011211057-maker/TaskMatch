
/* =========================================================
   TASKMATCH - COMPLETE JAVASCRIPT
   Compatible with TaskMatch Go Templates

   Features:
   1. Show / Hide Password
   2. Register Form Validation
   3. Login Form Validation
   4. Job Form Validation
   5. Confirm Important Actions
   6. Prevent Duplicate Submissions
   7. Mobile Navigation
   8. Dismissible Alerts
   9. Date Input Validation
   10. Utility Functions
========================================================= */

"use strict";

/* =========================================================
   1. INITIALIZE
========================================================= */

document.addEventListener("DOMContentLoaded", function () {
    initializePasswordToggles();
    initializeRegisterForm();
    initializeLoginForm();
    initializeJobForm();
    initializeConfirmButtons();
    initializeMobileNavigation();
    initializeAlerts();
    initializeFormSubmissionProtection();
});

/* =========================================================
   2. SHOW / HIDE PASSWORD
========================================================= */

function initializePasswordToggles() {
    const toggleButtons = document.querySelectorAll(
        "[data-toggle-password]"
    );

    toggleButtons.forEach(function (button) {
        button.addEventListener("click", function () {
            const inputId = button.getAttribute(
                "data-toggle-password"
            );

            if (!inputId) {
                return;
            }

            const passwordInput = document.getElementById(inputId);

            if (!passwordInput) {
                return;
            }

            const isHidden = passwordInput.type === "password";

            passwordInput.type = isHidden ? "text" : "password";

            button.setAttribute(
                "aria-pressed",
                String(isHidden)
            );

            button.setAttribute(
                "aria-label",
                isHidden ? "ซ่อนรหัสผ่าน" : "แสดงรหัสผ่าน"
            );

            button.textContent = isHidden ? "ซ่อน" : "แสดง";
        });
    });
}

/* =========================================================
   3. REGISTER FORM
========================================================= */

function initializeRegisterForm() {
    const registerForm = document.getElementById("registerForm");

    if (!registerForm) {
        return;
    }

    const nameInput = document.getElementById("name");
    const emailInput = document.getElementById("email");
    const passwordInput = document.getElementById("password");
    const confirmPasswordInput = document.getElementById(
        "confirmPassword"
    );
    const passwordMatchError = document.getElementById(
        "passwordMatchError"
    );

    if (
        !nameInput ||
        !emailInput ||
        !passwordInput ||
        !confirmPasswordInput
    ) {
        return;
    }

    function clearPasswordError() {
        confirmPasswordInput.setCustomValidity("");

        if (passwordMatchError) {
            passwordMatchError.hidden = true;
        }
    }

    passwordInput.addEventListener("input", function () {
        passwordInput.setCustomValidity("");
        clearPasswordError();
    });

    confirmPasswordInput.addEventListener(
        "input",
        clearPasswordError
    );

    nameInput.addEventListener("input", function () {
        nameInput.setCustomValidity("");
    });

    emailInput.addEventListener("input", function () {
        emailInput.setCustomValidity("");
    });

    registerForm.addEventListener("submit", function (event) {
        clearPasswordError();

        const name = nameInput.value.trim();
        const email = emailInput.value.trim();
        const password = passwordInput.value;
        const confirmPassword = confirmPasswordInput.value;

        if (!name) {
            event.preventDefault();

            nameInput.setCustomValidity(
                "กรุณากรอกชื่อผู้ใช้งาน"
            );

            nameInput.reportValidity();
            return;
        }

        nameInput.setCustomValidity("");

        if (!email) {
            event.preventDefault();

            emailInput.setCustomValidity(
                "กรุณากรอกอีเมล"
            );

            emailInput.reportValidity();
            return;
        }

        emailInput.setCustomValidity("");

        if (password.length < 8) {
            event.preventDefault();

            passwordInput.setCustomValidity(
                "รหัสผ่านต้องมีอย่างน้อย 8 ตัวอักษร"
            );

            passwordInput.reportValidity();
            return;
        }

        passwordInput.setCustomValidity("");

        /*
           ตรวจสอบความยาวรหัสผ่านในรูปแบบ UTF-8
           เพื่อให้สอดคล้องกับข้อจำกัด bcrypt
        */

        const passwordBytes = new TextEncoder()
            .encode(password)
            .length;

        if (passwordBytes > 72) {
            event.preventDefault();

            passwordInput.setCustomValidity(
                "รหัสผ่านต้องไม่เกิน 72 ไบต์"
            );

            passwordInput.reportValidity();
            return;
        }

        if (password !== confirmPassword) {
            event.preventDefault();

            confirmPasswordInput.setCustomValidity(
                "รหัสผ่านทั้งสองช่องไม่ตรงกัน"
            );

            if (passwordMatchError) {
                passwordMatchError.hidden = false;
            }

            confirmPasswordInput.reportValidity();
            return;
        }

        const selectedRole = registerForm.querySelector(
            'input[name="role"]:checked'
        );

        if (!selectedRole) {
            event.preventDefault();

            const firstRole = registerForm.querySelector(
                'input[name="role"]'
            );

            if (firstRole) {
                firstRole.reportValidity();
            }

            return;
        }

        if (
            selectedRole.value !== "customer" &&
            selectedRole.value !== "worker"
        ) {
            event.preventDefault();
            window.alert("ประเภทบัญชีไม่ถูกต้อง");
            return;
        }

        /*
           ผ่านการตรวจสอบเบื้องต้นแล้ว
           Browser ส่ง POST /register
           Backend ต้องตรวจสอบซ้ำอีกครั้ง
        */
    });
}

/* =========================================================
   4. LOGIN FORM
========================================================= */

function initializeLoginForm() {
    const loginForm = document.getElementById("loginForm");

    if (!loginForm) {
        return;
    }

    const emailInput = loginForm.querySelector(
        'input[name="email"]'
    );

    const passwordInput = loginForm.querySelector(
        'input[name="password"]'
    );

    if (!emailInput || !passwordInput) {
        return;
    }

    loginForm.addEventListener("submit", function (event) {
        const email = emailInput.value.trim();
        const password = passwordInput.value;

        if (!email) {
            event.preventDefault();

            emailInput.setCustomValidity(
                "กรุณากรอกอีเมล"
            );

            emailInput.reportValidity();
            return;
        }

        emailInput.setCustomValidity("");

        if (!password) {
            event.preventDefault();

            passwordInput.setCustomValidity(
                "กรุณากรอกรหัสผ่าน"
            );

            passwordInput.reportValidity();
            return;
        }

        passwordInput.setCustomValidity("");

        /*
           ส่ง POST /login
           การตรวจสอบรหัสผ่านจริงทำที่ Backend
        */
    });

    emailInput.addEventListener("input", function () {
        emailInput.setCustomValidity("");
    });

    passwordInput.addEventListener("input", function () {
        passwordInput.setCustomValidity("");
    });
}

/* =========================================================
   5. CREATE / EDIT JOB FORM
========================================================= */

function initializeJobForm() {
    const jobForm = document.getElementById("jobForm");

    if (!jobForm) {
        return;
    }

    const titleInput = document.getElementById("title");
    const categoryInput = document.getElementById("category_id");
    const descriptionInput = document.getElementById("description");
    const priceInput = document.getElementById("price");
    const deadlineInput = document.getElementById("deadline");

    if (
        !titleInput ||
        !categoryInput ||
        !descriptionInput ||
        !priceInput ||
        !deadlineInput
    ) {
        return;
    }

    function getLocalDateString() {
        const now = new Date();

        const year = now.getFullYear();

        const month = String(
            now.getMonth() + 1
        ).padStart(2, "0");

        const day = String(
            now.getDate()
        ).padStart(2, "0");

        return `${year}-${month}-${day}`;
    }

    const isEditForm = jobForm.action.includes("/edit");

    /*
       ลงประกาศใหม่:
       ไม่อนุญาตวันที่ย้อนหลัง

       แก้ไข:
       อนุญาตให้แสดงวันที่เดิม แม้วันที่ผ่านไปแล้ว
       การตรวจสอบสุดท้ายเป็นหน้าที่ Backend
    */

    if (!isEditForm) {
        deadlineInput.min = getLocalDateString();
    }

    jobForm.addEventListener("submit", function (event) {
        const title = titleInput.value.trim();
        const category = categoryInput.value;
        const description = descriptionInput.value.trim();
        const priceText = priceInput.value.trim();
        const price = Number(priceText);
        const deadline = deadlineInput.value;
        const today = getLocalDateString();

        if (!title) {
            event.preventDefault();

            titleInput.setCustomValidity(
                "กรุณากรอกชื่องาน"
            );

            titleInput.reportValidity();
            return;
        }

        titleInput.setCustomValidity("");

        if (!category) {
            event.preventDefault();

            categoryInput.setCustomValidity(
                "กรุณาเลือกหมวดหมู่งาน"
            );

            categoryInput.reportValidity();
            return;
        }

        categoryInput.setCustomValidity("");

        if (!description) {
            event.preventDefault();

            descriptionInput.setCustomValidity(
                "กรุณากรอกรายละเอียดงาน"
            );

            descriptionInput.reportValidity();
            return;
        }

        descriptionInput.setCustomValidity("");

        if (
            priceText === "" ||
            !Number.isFinite(price) ||
            price < 0 ||
            price > 99999999.99
        ) {
            event.preventDefault();

            priceInput.setCustomValidity(
                "กรุณาระบุค่าจ้างตั้งแต่ 0 ถึง 99,999,999.99 บาท"
            );

            priceInput.reportValidity();
            return;
        }

        priceInput.setCustomValidity("");

        if (!deadline) {
            event.preventDefault();

            deadlineInput.setCustomValidity(
                "กรุณาเลือกกำหนดส่งงาน"
            );

            deadlineInput.reportValidity();
            return;
        }

        if (!isEditForm && deadline < today) {
            event.preventDefault();

            deadlineInput.setCustomValidity(
                "กำหนดส่งงานต้องไม่เป็นวันที่ย้อนหลัง"
            );

            deadlineInput.reportValidity();
            return;
        }

        deadlineInput.setCustomValidity("");

        /*
           ผ่านการตรวจสอบแล้ว

           เพิ่มงาน:
           POST /jobs/new

           แก้ไขงาน:
           POST /jobs/{id}/edit

           Backend ต้องตรวจสอบข้อมูลซ้ำ
        */
    });

    titleInput.addEventListener("input", function () {
        titleInput.setCustomValidity("");
    });

    categoryInput.addEventListener("change", function () {
        categoryInput.setCustomValidity("");
    });

    descriptionInput.addEventListener("input", function () {
        descriptionInput.setCustomValidity("");
    });

    priceInput.addEventListener("input", function () {
        priceInput.setCustomValidity("");
    });

    deadlineInput.addEventListener("input", function () {
        deadlineInput.setCustomValidity("");
    });

    deadlineInput.addEventListener("change", function () {
        deadlineInput.setCustomValidity("");
    });
}

/* =========================================================
   6. CONFIRM IMPORTANT ACTIONS
========================================================= */

function initializeConfirmButtons() {
    /*
       รองรับปุ่มที่มี data-confirm เช่น

       <button
           type="submit"
           data-confirm="ยืนยันการลบประกาศงานนี้?"
       >
           ลบงาน
       </button>

       ไม่ต้องใช้ onclick แบบ inline
    */

    const confirmButtons = document.querySelectorAll(
        "[data-confirm]"
    );

    confirmButtons.forEach(function (button) {
        button.addEventListener("click", function (event) {
            const message = button.getAttribute("data-confirm");

            if (!message) {
                return;
            }

            /*
               ถ้าปุ่มอยู่ในฟอร์ม ให้ตรวจสอบข้อมูลก่อน
               เพื่อไม่แสดงกล่องยืนยันโดยไม่จำเป็น
            */

            const form = button.closest("form");

            if (
                form &&
                button.type === "submit" &&
                !form.checkValidity()
            ) {
                return;
            }

            const confirmed = window.confirm(message);

            if (!confirmed) {
                event.preventDefault();
                event.stopImmediatePropagation();
            }
        });
    });
}

/* =========================================================
   7. PREVENT DUPLICATE FORM SUBMISSION
========================================================= */

function initializeFormSubmissionProtection() {
    const forms = document.querySelectorAll("form");

    forms.forEach(function (form) {
        let isSubmitting = false;

        function resetSubmissionState() {
            isSubmitting = false;

            const submitButtons = form.querySelectorAll(
                'button[type="submit"], input[type="submit"]'
            );

            submitButtons.forEach(function (button) {
                button.classList.remove("is-submitting");
                button.removeAttribute("aria-disabled");
            });
        }

        form.addEventListener("submit", function (event) {
            /*
               หากฟังก์ชันตรวจสอบข้อมูลก่อนหน้า
               สั่ง preventDefault() แล้ว
               ห้ามล็อกฟอร์ม
            */

            if (event.defaultPrevented) {
                return;
            }

            if (!form.checkValidity()) {
                return;
            }

            if (isSubmitting) {
                event.preventDefault();
                return;
            }

            isSubmitting = true;

            const submitButtons = form.querySelectorAll(
                'button[type="submit"], input[type="submit"]'
            );

            submitButtons.forEach(function (button) {
                button.classList.add("is-submitting");
                button.setAttribute("aria-disabled", "true");
            });
        });

        /*
           เมื่อผู้ใช้ย้อนกลับมาหน้าเดิม
           ให้สามารถส่งฟอร์มใหม่ได้
        */

        window.addEventListener(
            "pageshow",
            resetSubmissionState
        );
    });
}

/* =========================================================
   8. MOBILE NAVIGATION
========================================================= */

function initializeMobileNavigation() {
    const menuButton = document.querySelector(
        ".menu-toggle, .mobile-menu-toggle"
    );

    const navigation = document.querySelector(
        ".tm-nav-links, .nav-links, .nav-menu, .navbar-links"
    );

    if (!menuButton || !navigation) {
        return;
    }

    menuButton.setAttribute("aria-expanded", "false");

    menuButton.addEventListener("click", function () {
        const isOpen = navigation.classList.toggle("nav-open");

        menuButton.setAttribute(
            "aria-expanded",
            String(isOpen)
        );

        menuButton.setAttribute(
            "aria-label",
            isOpen ? "ปิดเมนู" : "เปิดเมนู"
        );
    });

    navigation.querySelectorAll("a").forEach(function (link) {
        link.addEventListener("click", function () {
            navigation.classList.remove("nav-open");

            menuButton.setAttribute(
                "aria-expanded",
                "false"
            );
        });
    });

    document.addEventListener("keydown", function (event) {
        if (event.key !== "Escape") {
            return;
        }

        navigation.classList.remove("nav-open");

        menuButton.setAttribute(
            "aria-expanded",
            "false"
        );
    });
}

/* =========================================================
   9. DISMISSIBLE ALERTS
========================================================= */

function initializeAlerts() {
    const alerts = document.querySelectorAll(
        ".alert[data-dismissible]"
    );

    alerts.forEach(function (alert) {
        const closeButton = alert.querySelector(
            "[data-dismiss-alert]"
        );

        if (!closeButton) {
            return;
        }

        closeButton.addEventListener("click", function () {
            alert.remove();
        });
    });
}

/* =========================================================
   10. OPTIONAL UTILITY FUNCTIONS
========================================================= */

/*
   จัดรูปแบบจำนวนเงินเป็นเงินบาท
*/

function formatThaiCurrency(amount) {
    const number = Number(amount);

    if (!Number.isFinite(number)) {
        return "฿0.00";
    }

    return new Intl.NumberFormat("th-TH", {
        style: "currency",
        currency: "THB"
    }).format(number);
}

/*
   ตรวจสอบรูปแบบอีเมลเบื้องต้น
   การตรวจสอบจริงต้องทำที่ Backend
*/

function isValidEmail(email) {
    if (typeof email !== "string") {
        return false;
    }

    const trimmedEmail = email.trim();

    if (!trimmedEmail) {
        return false;
    }

    const atIndex = trimmedEmail.indexOf("@");
    const lastDotIndex = trimmedEmail.lastIndexOf(".");

    return (
        atIndex > 0 &&
        lastDotIndex > atIndex + 1 &&
        lastDotIndex < trimmedEmail.length - 1
    );
}

/* =========================================================
   TASKMATCH - MARKETPLACE CATEGORY FILTER
   เพิ่มต่อท้าย static/js/script.js เดิม
========================================================= */

document.addEventListener("DOMContentLoaded", function () {
    initializeMarketplaceCategoryFilter();
});

function initializeMarketplaceCategoryFilter() {
    "use strict";

    const jobGrid = document.getElementById("tmJobGrid");

    const categoryButtons = document.querySelectorAll(
        "[data-marketplace-category]"
    );

    const jobCount = document.getElementById(
        "tmMarketplaceJobCount"
    );

    const emptyMessage = document.getElementById(
        "tmMarketplaceFilterEmpty"
    );

    // หากไม่ได้อยู่หน้าตลาดงาน ไม่ต้องทำอะไร
    if (!jobGrid || categoryButtons.length === 0) {
        return;
    }

    const jobCards = Array.from(
        jobGrid.querySelectorAll(
            ".tm-marketplace-card[data-job-category]"
        )
    );

    /*
       แปลงข้อความหมวดหมู่ให้อยู่ในรูปแบบเดียวกัน
       รองรับทั้งภาษาไทยและภาษาอังกฤษ
    */
    function normalizeCategory(value) {
        return String(value || "")
            .trim()
            .toLowerCase()
            .replace(/\s+/g, " ");
    }

    /*
       จัดหมวดหมู่จากค่าที่ Go Template ส่งมา

       ตัวอย่าง:
       "ทำความสะอาด" -> cleaning
       "ดูแลสัตว์เลี้ยง" -> pets
       "งานช่าง" -> repair
       "คอมพิวเตอร์" -> technology

       หมวดหมู่ที่ไม่รู้จัก -> other
    */
    function getCategoryGroup(categoryName) {
        const name = normalizeCategory(categoryName);

        if (!name) {
            return "other";
        }

        const groups = {
            cleaning: [
                "cleaning",
                "clean",
                "housekeeping",
                "ทำความสะอาด",
                "แม่บ้าน",
                "ซักรีด",
                "ล้างบ้าน",
                "ล้างรถ",
                "เก็บกวาด"
            ],

            pets: [
                "pets",
                "pet",
                "animal",
                "pet care",
                "เลี้ยงสัตว์",
                "สัตว์เลี้ยง",
                "ดูแลสัตว์",
                "ดูแลสัตว์เลี้ยง",
                "พาสุนัขเดินเล่น",
                "หมา",
                "แมว"
            ],

            repair: [
                "repair",
                "maintenance",
                "handyman",
                "technician",
                "งานช่าง",
                "ช่าง",
                "ซ่อม",
                "ซ่อมแซม",
                "ติดตั้ง",
                "ไฟฟ้า",
                "ประปา",
                "แอร์"
            ],

            technology: [
                "technology",
                "tech",
                "it",
                "computer",
                "programming",
                "developer",
                "website",
                "web development",
                "คอมพิวเตอร์",
                "ไอที",
                "เขียนโปรแกรม",
                "เว็บไซต์",
                "พัฒนาเว็บ",
                "ทำเว็บ",
                "โปรแกรม",
                "ซอฟต์แวร์"
            ],

            design: [
                "design",
                "graphic",
                "graphics",
                "illustration",
                "ออกแบบ",
                "กราฟิก",
                "ดีไซน์",
                "โลโก้",
                "วาดภาพ",
                "ตัดต่อ",
                "แต่งภาพ"
            ],

            marketing: [
                "marketing",
                "advertising",
                "social media",
                "promotion",
                "การตลาด",
                "โฆษณา",
                "โปรโมท",
                "ประชาสัมพันธ์",
                "ขายของ",
                "คอนเทนต์"
            ]
        };

        for (const groupName in groups) {
            if (
                !Object.prototype.hasOwnProperty.call(
                    groups,
                    groupName
                )
            ) {
                continue;
            }

            const keywords = groups[groupName];

            for (const keyword of keywords) {
                const normalizedKeyword =
                    normalizeCategory(keyword);

                if (name === normalizedKeyword) {
                    return groupName;
                }

                // คำทั่วไปที่มีความยาวพอ สามารถค้นหาแบบบางส่วนได้
                if (
                    normalizedKeyword.length >= 4 &&
                    name.includes(normalizedKeyword)
                ) {
                    return groupName;
                }
            }
        }

        return "other";
    }

    /*
       เตรียมหมวดหมู่ของแต่ละการ์ด
       เพื่อไม่ต้องคำนวณซ้ำทุกครั้งที่คลิก
    */
    const jobs = jobCards.map(function (card) {
        const rawCategory =
            card.getAttribute("data-job-category");

        return {
            element: card,
            category: getCategoryGroup(rawCategory)
        };
    });

    /*
       แสดงงานเฉพาะหมวดหมู่ที่เลือก
    */
    function filterJobs(selectedCategory) {
        let visibleCount = 0;

        jobs.forEach(function (job) {
            const shouldShow =
                selectedCategory === "all" ||
                job.category === selectedCategory;

            job.element.hidden = !shouldShow;

            // ป้องกัน CSS display:grid/flex
            // ทำให้การ์ดที่ซ่อนไว้กลับมาแสดง
            job.element.style.display =
                shouldShow ? "" : "none";

            if (shouldShow) {
                visibleCount++;
            }
        });

        // อัปเดตจำนวนงาน
        if (jobCount) {
            jobCount.textContent =
                visibleCount.toLocaleString("th-TH") + " งาน";
        }

        // แสดงข้อความเมื่อไม่มีงานในหมวดหมู่
        if (emptyMessage) {
            const isEmpty = visibleCount === 0;

            emptyMessage.hidden = !isEmpty;
            emptyMessage.style.display =
                isEmpty ? "block" : "none";
        }

        // อัปเดตสถานะปุ่ม
        categoryButtons.forEach(function (button) {
            const buttonCategory =
                button.getAttribute(
                    "data-marketplace-category"
                );

            const isActive =
                buttonCategory === selectedCategory;

            button.classList.toggle(
                "is-active",
                isActive
            );

            button.setAttribute(
                "aria-pressed",
                String(isActive)
            );
        });
    }

    /*
       เมื่อคลิกปุ่มหมวดหมู่
    */
    categoryButtons.forEach(function (button) {
        button.addEventListener("click", function () {
            const selectedCategory =
                button.getAttribute(
                    "data-marketplace-category"
                ) || "all";

            filterJobs(selectedCategory);
        });
    });

    // ค่าเริ่มต้น: แสดงงานทั้งหมด
    filterJobs("all");
}
document.addEventListener("DOMContentLoaded", function () {
    const currentPath = window.location.pathname;

    document.querySelectorAll("[data-nav-path]").forEach(function (link) {
        const targetPath = link.getAttribute("data-nav-path");

        const isActive =
            targetPath === "/"
                ? currentPath === "/"
                : currentPath === targetPath ||
                  currentPath.startsWith(targetPath + "/");

        link.classList.toggle("is-current-page", isActive);

        if (isActive) {
            link.setAttribute("aria-current", "page");
        } else {
            link.removeAttribute("aria-current");
        }
    });
});
/* =========================================================
   END - MARKETPLACE CATEGORY FILTER
========================================================= */

/* =========================================================
   END OF TASKMATCH JAVASCRIPT
========================================================= */
