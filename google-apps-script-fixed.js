/**
 * Google Apps Script for Pawn Shop Form - FIXED VERSION
 * 
 * Instructions:
 * 1. Go to https://script.google.com
 * 2. Open your existing project
 * 3. Replace the code with this version
 * 4. Save and redeploy
 */

// REPLACE THIS WITH YOUR GOOGLE SHEET ID
// Get it from the URL: https://docs.google.com/spreadsheets/d/YOUR_SHEET_ID/edit
const SHEET_ID = '1zkWc22g7h7I1_rHPvlZTMXlSLIaSeETmqhMQN6YNHwk'; // Your actual sheet ID

function doPost(e) {
  try {
    let data;
    
    // Handle both JSON and form-encoded data
    if (e.postData && e.postData.contents) {
      try {
        // Try to parse as JSON first
        data = JSON.parse(e.postData.contents);
      } catch (jsonError) {
        // If JSON parsing fails, parse as form data
        const formData = e.parameter;
        data = {
          pawnNumber: formData.pawnNumber || '',
          customerName: formData.customerName || '',
          fatherHusbandName: formData.fatherHusbandName || '',
          address: formData.address || '',
          dateOfPawn: formData.dateOfPawn || '',
          amount: formData.amount || '',
          weight: formData.weight || '',
          articleDescription: formData.articleDescription || ''
        };
      }
    } else {
      // Handle direct form submission
      data = {
        pawnNumber: e.parameter.pawnNumber || '',
        customerName: e.parameter.customerName || '',
        fatherHusbandName: e.parameter.fatherHusbandName || '',
        address: e.parameter.address || '',
        dateOfPawn: e.parameter.dateOfPawn || '',
        amount: e.parameter.amount || '',
        weight: e.parameter.weight || '',
        articleDescription: e.parameter.articleDescription || ''
      };
    }
    
    // Get the specific spreadsheet by ID
    const spreadsheet = SpreadsheetApp.openById(SHEET_ID);
    const sheet = spreadsheet.getActiveSheet();
    
    // Create headers if they don't exist
    const headers = [
      'Pledge Number', 
      'Customer Name',
      'Father/Husband Name',
      'Address',
      'Date of Pawn',
      'Amount',
      'Weight (grams)',
      'Article Description',
      'Submission Time'
    ];
    
    // Check if headers exist, if not create them
    if (sheet.getLastRow() === 0) {
      sheet.getRange(1, 1, 1, headers.length).setValues([headers]);
      // Format headers
      sheet.getRange(1, 1, 1, headers.length).setFontWeight('bold');
      sheet.getRange(1, 1, 1, headers.length).setBackground('#d4af37');
    }
    
    // Prepare the row data with timestamp
    const rowData = [
      data.pawnNumber || '',
      data.customerName || '',
      data.fatherHusbandName || '',
      data.address || '',
      data.dateOfPawn || '',
      data.amount || '',
      data.weight || '',
      data.articleDescription || '',
      new Date().toLocaleString() // Add submission timestamp
    ];
    
    // Add the new row
    sheet.appendRow(rowData);
    
    // Auto-resize columns
    sheet.autoResizeColumns(1, headers.length);
    
    // Return success response
    return ContentService
      .createTextOutput(JSON.stringify({
        success: true,
        message: 'Article submitted successfully!',
        pawnNumber: data.pawnNumber,
        timestamp: new Date().toISOString()
      }))
      .setMimeType(ContentService.MimeType.JSON);
      
  } catch (error) {
    // Log the error for debugging
    console.error('Google Apps Script Error:', error);
    
    // Return error response
    return ContentService
      .createTextOutput(JSON.stringify({
        success: false,
        message: 'Error submitting article: ' + error.toString(),
        error: error.toString()
      }))
      .setMimeType(ContentService.MimeType.JSON);
  }
}

function doGet(e) {
  // Simple test endpoint
  return ContentService
    .createTextOutput(JSON.stringify({
      status: 'OK',
      message: 'Pawn Shop Google Apps Script is running!',
      sheetId: SHEET_ID,
      timestamp: new Date().toISOString()
    }))
    .setMimeType(ContentService.MimeType.JSON);
}

// Test function to verify sheet access
function testSheetAccess() {
  try {
    const spreadsheet = SpreadsheetApp.openById(SHEET_ID);
    const sheet = spreadsheet.getActiveSheet();
    const name = sheet.getName();
    return `Successfully connected to sheet: ${name}`;
  } catch (error) {
    return `Error connecting to sheet: ${error.toString()}`;
  }
}
