import { Controller, Get, Res } from '@nestjs/common';
import { Response } from 'express';
import * as path from 'path';

@Controller()
export class AppController {
  @Get()
  serveIndex(@Res() res: Response) {
    const filePath = path.join(__dirname, '..', 'public', 'index.html');
    res.sendFile(filePath);
  }
}
