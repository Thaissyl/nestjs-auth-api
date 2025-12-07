import { Body, Controller, Post, Res, Req, HttpCode, HttpStatus, UseGuards } from "@nestjs/common";
import { AuthService } from "./auth.service";
import { AuthDto } from "./dto";
import { Request, Response } from "express";
import { AuthGuard } from "@nestjs/passport";

@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService) {}

    @Post('signup')
    async signup(@Body() dto: AuthDto, @Res({ passthrough: true }) res: Response) {
        const tokens = await this.authService.signup(dto);
        
        // Set refresh token in httpOnly cookie
        res.cookie('refresh_token', tokens.refresh_token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        });

        return { access_token: tokens.access_token };
    }
    
    @HttpCode(HttpStatus.OK)
    @Post('signin')
    async signin(@Body() dto: AuthDto, @Res({ passthrough: true }) res: Response) {
        const tokens = await this.authService.signin(dto);
        
        // Set refresh token in httpOnly cookie
        res.cookie('refresh_token', tokens.refresh_token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        });

        return { access_token: tokens.access_token };
    }

    @UseGuards(AuthGuard('jwt'))
    @HttpCode(HttpStatus.OK)
    @Post('logout')
    async logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
        const user = req.user as { sub: number };
        await this.authService.logout(user.sub);
        
        // Clear refresh token cookie
        res.clearCookie('refresh_token');
        
        return { message: 'Logged out successfully' };
    }

    @HttpCode(HttpStatus.OK)
    @Post('refresh')
    async refreshTokens(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
        const refreshToken = req.cookies['refresh_token'];
        
        if (!refreshToken) {
            throw new Error('Refresh token not found');
        }

        // Decode token to get user id
        const decoded = await this.authService['jwt'].decode(refreshToken) as { sub: number };
        
        const tokens = await this.authService.refreshTokens(decoded.sub, refreshToken);
        
        // Set new refresh token in cookie
        res.cookie('refresh_token', tokens.refresh_token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        });

        return { access_token: tokens.access_token };
    }
}
