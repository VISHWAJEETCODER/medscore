const express = require('express');
const { uploadVideo, uploadMaterial, uploadMultiple, handleUploadError } = require('../middleware/upload');
const { authenticate, authorize } = require('../middleware/auth');
const path = require('path');
const fs = require('fs');

const router = express.Router();

/**
 * @route   POST /api/uploads/video
 * @desc    Upload college video
 * @access  Private (Admin only)
 */
router.post('/video', authenticate, authorize(['admin']), uploadVideo, handleUploadError, (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No video file uploaded' });
    }

    const videoData = {
      id: Date.now(),
      filename: req.file.filename,
      originalName: req.file.originalname,
      path: req.file.path,
      size: req.file.size,
      mimetype: req.file.mimetype,
      uploadedAt: new Date().toISOString(),
      uploadedBy: req.user.id
    };

    res.status(200).json({
      success: true,
      message: 'Video uploaded successfully',
      data: videoData
    });
  } catch (error) {
    console.error('Video upload error:', error);
    res.status(500).json({ error: 'Failed to upload video' });
  }
});

/**
 * @route   POST /api/uploads/material
 * @desc    Upload study material (PDF, documents)
 * @access  Private (Admin only)
 */
router.post('/material', authenticate, authorize(['admin']), uploadMaterial, handleUploadError, (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No material file uploaded' });
    }

    const materialData = {
      id: Date.now(),
      filename: req.file.filename,
      originalName: req.file.originalname,
      path: req.file.path,
      size: req.file.size,
      mimetype: req.file.mimetype,
      uploadedAt: new Date().toISOString(),
      uploadedBy: req.user.id
    };

    res.status(200).json({
      success: true,
      message: 'Material uploaded successfully',
      data: materialData
    });
  } catch (error) {
    console.error('Material upload error:', error);
    res.status(500).json({ error: 'Failed to upload material' });
  }
});

/**
 * @route   POST /api/uploads/multiple
 * @desc    Upload multiple files (videos, materials, images)
 * @access  Private (Admin only)
 */
router.post('/multiple', authenticate, authorize(['admin']), uploadMultiple, handleUploadError, (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ error: 'No files uploaded' });
    }

    const filesData = req.files.map(file => ({
      id: Date.now() + Math.random(),
      filename: file.filename,
      originalName: file.originalname,
      path: file.path,
      size: file.size,
      mimetype: file.mimetype,
      uploadedAt: new Date().toISOString(),
      uploadedBy: req.user.id
    }));

    res.status(200).json({
      success: true,
      message: `${req.files.length} files uploaded successfully`,
      data: filesData
    });
  } catch (error) {
    console.error('Multiple files upload error:', error);
    res.status(500).json({ error: 'Failed to upload files' });
  }
});

/**
 * @route   GET /api/uploads/files
 * @desc    Get list of uploaded files
 * @access  Private (Admin only)
 */
router.get('/files', authenticate, authorize(['admin']), (req, res) => {
  try {
    const uploadsDir = path.join(__dirname, '../uploads');
    const files = [];

    // Scan all upload directories
    const directories = ['videos', 'materials', 'college-videos', 'colleges', 'mentors', 'profiles', 'documents'];
    
    directories.forEach(dir => {
      const dirPath = path.join(uploadsDir, dir);
      if (fs.existsSync(dirPath)) {
        const dirFiles = fs.readdirSync(dirPath);
        dirFiles.forEach(file => {
          const filePath = path.join(dirPath, file);
          const stats = fs.statSync(filePath);
          
          files.push({
            id: Date.now() + Math.random(),
            filename: file,
            directory: dir,
            path: filePath,
            size: stats.size,
            uploadedAt: stats.birthtime,
            type: path.extname(file).toLowerCase()
          });
        });
      }
    });

    res.status(200).json({
      success: true,
      data: files
    });
  } catch (error) {
    console.error('Get files error:', error);
    res.status(500).json({ error: 'Failed to get files list' });
  }
});

/**
 * @route   DELETE /api/uploads/file/:filename
 * @desc    Delete uploaded file
 * @access  Private (Admin only)
 */
router.delete('/file/:filename', authenticate, authorize(['admin']), (req, res) => {
  try {
    const { filename } = req.params;
    const uploadsDir = path.join(__dirname, '../uploads');
    const directories = ['videos', 'materials', 'college-videos', 'colleges', 'mentors', 'profiles', 'documents'];
    
    let fileDeleted = false;
    
    directories.forEach(dir => {
      const filePath = path.join(uploadsDir, dir, filename);
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
        fileDeleted = true;
      }
    });

    if (fileDeleted) {
      res.status(200).json({
        success: true,
        message: 'File deleted successfully'
      });
    } else {
      res.status(404).json({ error: 'File not found' });
    }
  } catch (error) {
    console.error('Delete file error:', error);
    res.status(500).json({ error: 'Failed to delete file' });
  }
});

module.exports = router;
