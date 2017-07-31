%                             Copyright (C) <2017> 
%                        Mahdieh ZabihiMayvan, Reza Sadeghi   
%     Department of Computer Science and Engineering, Kno.e.sis Research Center, 
%                Wright State University, Dayton, OH, USA
% 
%     This program is free software: you can redistribute it and/or modify
%     it under the terms of the GNU General Public License as published by
%     the Free Software Foundation, either version 3 of the License, or
%     any later version.
% 
%     This program is distributed under the License on an "AS IS" BASIS,
%     but WITHOUT ANY WARRANTY; without even the implied warranty of
%     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
%     GNU General Public License for more details.
% 
%     You should have received a copy of the GNU General Public License
%     along with this program.  If not, see <http://www.gnu.org/licenses/>.
%
%     Using this code or any associated file of this package in a publication, 
%     please CITE the related paper as below:
%
%     Zabihimayvan, Mahdieh, Reza Sadeghi, H. Nathan Rude, and Derek Doran. 
%     "A Soft Computing Approach for Benign and Malicious Web Robot Detection." 
%     Expert Systems with Applications 87 (2017) 129-140.

%     If you have any questions concerning the implementation of the code, 
%     please feel free to contact us via email addresses below:

%     Zabhimayvan.2@wright.edu, mahdieh@knoesis.org, sadeghi.2@wright.edu,
%     reza@knoesis.org.



function [TPCategory, TNCategory, FPCategory, FNCategory, TP, FP, TN, FN]=DBSCAN(Train,Test,epsilon,MinPts)
%% Train
global tt
tt=0;
disp('Training DBSCAN starts')
    C=0;
    Data=Train(:,1:end-1);  
    FeatureNumber=size(Data,2);
    n=size(Data,1);
    IDX=zeros(n,1);
    
    visited=false(n,1);
    isnoise=false(n,1);
    
    for i=1:n
        if ~visited(i)
            visited(i)=true;
            tt=tt+1;
            disp(tt)
            
            Neighbors=RegionQuery(i);
            if numel(Neighbors)<MinPts
                % X(i,:) is NOISE
                isnoise(i)=true;
            else
                C=C+1;
                ExpandCluster(i,Neighbors,C);
            end
            
        end
    
    end
    
    function ExpandCluster(i,Neighbors,C)
        IDX(i)=C;
        
        k = 1;
        while true
            j = Neighbors(k);
            
            if ~visited(j)
                visited(j)=true;
                tt=tt+1;
                disp(tt)
                Neighbors2=RegionQuery(j);
                if numel(Neighbors2)>=MinPts
                    Neighbors2=setdiff(Neighbors2,Neighbors);
                    Neighbors=[Neighbors; Neighbors2];
                    
                    if IDX(j)==0
                        IDX(j)=C;
                    end
                end
            end
            
            
            k = k + 1;
            if k > numel(Neighbors)
                break;
            end
        end
    end
    
    function Neighbors=RegionQuery(i)
        Temp=repmat(Data(i,:),[n 1]);
        D=sqrt(sum(((Temp-Data).^2)')');%Euclidean distance
        Neighbors=find(D<=epsilon);
    end
disp('Training DBSCAN is finished')

%% Recognizing cluster centers and their categories: 0->Humans' behaviour 1->Robots' behaviour
CategoryNumber=max(IDX);
Center=zeros(CategoryNumber,FeatureNumber+1);
for i=1:CategoryNumber%Consider just clusters and ignore noises
    Temp=find(IDX==i);
    Center(i,:)=sum(Train(Temp,:))/numel(Temp);
    Center(i,end)=(Center(i,end)>.5);
end

%% Diagnosis the test samples clusteres and categories
TestNumber=size(Test,1);
Label=zeros(TestNumber,1);
for i=1:TestNumber
    Distance=zeros(CategoryNumber,1);
    for j=1:CategoryNumber
        %Euclidean distance
        Distance(j)=sqrt(sum((Test(i,1:end-1)-Center(j,1:end-1)).^2));
    end
    Temp=find(Distance==min(Distance));
    if(numel(Temp)==1)
        Label(i)=Center(Temp,end);
    else
        Label(i)=(sum(Center(Temp,end))/numel(Temp)>.5);
    end
end

%% Computing TP, FP, TN, FN ->P:Robots' behaviour N:Humans' behaviour
TPCategory=find((Test(:,end)+Label)==2);
TNCategory=find((Test(:,end)+Label)==0);

FNCategory=find((Test(:,end)-Label)==1);
FPCategory=find((Test(:,end)-Label)==-1);

TP=numel(TPCategory);
TN=numel(TNCategory);
FP=numel(FPCategory);
FN=numel(FNCategory);
end