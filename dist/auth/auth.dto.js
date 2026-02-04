"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.RefreshTokenDto = exports.Verify2FADto = exports.LoginDto = exports.RegisterDto = void 0;
const class_validator_1 = require("class-validator");
const class_transformer_1 = require("class-transformer");
class RegisterDto {
}
exports.RegisterDto = RegisterDto;
__decorate([
    (0, class_validator_1.IsEmail)({}, { message: 'Invalid email format' }),
    (0, class_transformer_1.Transform)(({ value }) => value?.trim().toLowerCase()),
    __metadata("design:type", String)
], RegisterDto.prototype, "email", void 0);
__decorate([
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.MinLength)(6, { message: 'Password must be at least 6 characters' }),
    (0, class_validator_1.MaxLength)(128, { message: 'Password must not exceed 128 characters' }),
    __metadata("design:type", String)
], RegisterDto.prototype, "password", void 0);
class LoginDto {
}
exports.LoginDto = LoginDto;
__decorate([
    (0, class_validator_1.IsEmail)({}, { message: 'Invalid email format' }),
    (0, class_transformer_1.Transform)(({ value }) => value?.trim().toLowerCase()),
    __metadata("design:type", String)
], LoginDto.prototype, "email", void 0);
__decorate([
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.MinLength)(6, { message: 'Password must be at least 6 characters' }),
    __metadata("design:type", String)
], LoginDto.prototype, "password", void 0);
class Verify2FADto {
}
exports.Verify2FADto = Verify2FADto;
__decorate([
    (0, class_validator_1.IsEmail)({}, { message: 'Invalid email format' }),
    (0, class_transformer_1.Transform)(({ value }) => value?.trim().toLowerCase()),
    __metadata("design:type", String)
], Verify2FADto.prototype, "email", void 0);
__decorate([
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.Matches)(/^\d{6}$/, { message: '2FA code must be exactly 6 digits' }),
    __metadata("design:type", String)
], Verify2FADto.prototype, "code", void 0);
class RefreshTokenDto {
}
exports.RefreshTokenDto = RefreshTokenDto;
__decorate([
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], RefreshTokenDto.prototype, "refresh_token", void 0);
//# sourceMappingURL=auth.dto.js.map