import { createClient } from '@supabase/supabase-js';
import type { Scan, UserFeedbackReport, ReportType } from '../../supabase/types';

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || 'https://placeholder-quishguard.supabase.co';
const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.placeholder';

export const isSupabaseConfigured = () => {
  return (
    !!process.env.NEXT_PUBLIC_SUPABASE_URL &&
    !!process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY &&
    !process.env.NEXT_PUBLIC_SUPABASE_URL.includes('placeholder-quishguard')
  );
};

export const supabase = createClient(supabaseUrl, supabaseAnonKey);

/**
 * Save an inspection result to Supabase
 */
export async function saveScanToSupabase(scanData: Partial<Scan>): Promise<Scan | null> {
  if (!isSupabaseConfigured()) {
    return null;
  }
  const { data, error } = await supabase
    .from('scans')
    .insert([scanData])
    .select()
    .single();

  if (error) {
    console.error('Error saving scan to Supabase:', error);
    return null;
  }
  return data as Scan;
}

/**
 * Fetch a scan by its ID (for public shareable report URLs)
 */
export async function getScanById(id: string): Promise<Scan | null> {
  if (!isSupabaseConfigured()) {
    return null;
  }
  const { data, error } = await supabase
    .from('scans')
    .select('*')
    .eq('id', id)
    .single();

  if (error) {
    console.error(`Error fetching scan ${id}:`, error);
    return null;
  }
  return data as Scan;
}

/**
 * Fetch recent scans for live feed or analytics
 */
export async function getRecentScans(limit = 10): Promise<Scan[]> {
  if (!isSupabaseConfigured()) {
    return [];
  }
  const { data, error } = await supabase
    .from('scans')
    .select('*')
    .order('created_at', { ascending: false })
    .limit(limit);

  if (error) {
    console.error('Error fetching recent scans:', error);
    return [];
  }
  return (data || []) as Scan[];
}

/**
 * Submit user feedback or report a malicious QR
 */
export async function submitScanFeedback(
  scanId: string,
  reportType: ReportType,
  notes?: string
): Promise<UserFeedbackReport | null> {
  const { data, error } = await supabase
    .from('user_feedback_reports')
    .insert([{
      scan_id: scanId,
      report_type: reportType,
      feedback_notes: notes
    }])
    .select()
    .single();

  if (error) {
    console.error('Error submitting feedback:', error);
    return null;
  }
  return data as UserFeedbackReport;
}

/**
 * Upload a QR code image to Supabase Storage bucket 'qr-codes'
 */
export async function uploadQrCodeImage(file: File | Blob, fileName: string): Promise<string | null> {
  const cleanFileName = `${Date.now()}-${fileName.replace(/[^a-zA-Z0-9.-]/g, '_')}`;
  const { data, error } = await supabase.storage
    .from('qr-codes')
    .upload(cleanFileName, file, {
      contentType: file.type || 'image/png',
      upsert: false
    });

  if (error) {
    console.error('Error uploading QR code image:', error);
    return null;
  }

  // Get public URL
  const { data: publicUrlData } = supabase.storage
    .from('qr-codes')
    .getPublicUrl(data.path);

  return publicUrlData.publicUrl;
}
